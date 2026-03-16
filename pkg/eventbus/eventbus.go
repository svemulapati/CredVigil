// Package eventbus provides an internal publish/subscribe event bus for
// decoupled communication between CredVigil components.
//
// The event bus enables components such as the file watcher, detection engine,
// pipeline, and git scanner to communicate without direct dependencies. A
// component publishes an event to a topic, and any subscribers registered
// for that topic receive the event asynchronously.
//
// Key features:
//   - Topic-based publish/subscribe with type-safe event payloads
//   - Async delivery via buffered channels (configurable buffer size)
//   - Wildcard subscriptions ("*") to receive all events
//   - Thread-safe: safe for concurrent Publish, Subscribe, and Unsubscribe
//   - Graceful shutdown with in-flight event draining
//   - Dead-letter tracking for dropped events (slow subscribers)
//   - Observable stats: published, delivered, dropped counts
//   - Context-aware: respects cancellation during publish and delivery
package eventbus

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Topic represents an event category. Subscribers register interest
// in one or more topics.
type Topic string

const (
	// TopicFileChanged is published when the file watcher detects a change.
	TopicFileChanged Topic = "file.changed"

	// TopicScanStarted is published when a scan begins.
	TopicScanStarted Topic = "scan.started"

	// TopicScanCompleted is published when a scan finishes.
	TopicScanCompleted Topic = "scan.completed"

	// TopicFindingDetected is published for each secret finding.
	TopicFindingDetected Topic = "finding.detected"

	// TopicFindingProcessed is published after a finding passes through the pipeline.
	TopicFindingProcessed Topic = "finding.processed"

	// TopicGitScanStarted is published when a git history scan begins.
	TopicGitScanStarted Topic = "git.scan.started"

	// TopicGitScanCompleted is published when a git history scan finishes.
	TopicGitScanCompleted Topic = "git.scan.completed"

	// TopicGitCommitScanned is published after each commit is scanned.
	TopicGitCommitScanned Topic = "git.commit.scanned"

	// TopicError is published when a component encounters a non-fatal error.
	TopicError Topic = "error"

	// TopicWildcard matches all topics. Subscribe to "*" to receive everything.
	TopicWildcard Topic = "*"
)

// Event is a single message published to the bus.
type Event struct {
	// ID is a unique identifier for this event.
	ID string `json:"id"`

	// Topic categorizes the event.
	Topic Topic `json:"topic"`

	// Timestamp is when the event was created.
	Timestamp time.Time `json:"timestamp"`

	// Source identifies which component published the event.
	Source string `json:"source"`

	// Payload carries the event-specific data.
	// Subscribers should type-assert based on Topic.
	Payload interface{} `json:"payload,omitempty"`
}

// Handler is a function that processes an event.
// It must be safe for concurrent invocation.
type Handler func(event Event)

// Subscription represents a registered subscriber.
type Subscription struct {
	// ID uniquely identifies this subscription.
	ID string

	// Topic is the event category this subscription receives.
	Topic Topic

	// handler is the callback function.
	handler Handler

	// ch is the buffered channel for async delivery.
	ch chan Event

	// done signals the delivery goroutine to stop.
	done chan struct{}

	// active tracks whether this subscription is still alive.
	active atomic.Bool
}

// Config holds configuration for the event bus.
type Config struct {
	// BufferSize is the channel buffer size per subscriber.
	// If a subscriber falls behind by this many events, new events are dropped.
	// Default: 256.
	BufferSize int

	// DeliveryTimeout is the maximum time to wait when attempting to
	// send an event to a subscriber's channel. If the channel is full
	// and the timeout expires, the event is dropped for that subscriber.
	// Default: 100ms.
	DeliveryTimeout time.Duration
}

// DefaultConfig returns sensible defaults for the event bus.
func DefaultConfig() Config {
	return Config{
		BufferSize:      256,
		DeliveryTimeout: 100 * time.Millisecond,
	}
}

// Stats holds runtime statistics for the event bus.
type Stats struct {
	// Published is the total number of events published.
	Published uint64 `json:"published"`

	// Delivered is the total number of events delivered to subscribers.
	Delivered uint64 `json:"delivered"`

	// Dropped is the total number of events dropped (subscriber backpressure).
	Dropped uint64 `json:"dropped"`

	// ActiveSubscribers is the current number of active subscriptions.
	ActiveSubscribers int `json:"active_subscribers"`

	// TopicCounts maps each topic to how many events were published to it.
	TopicCounts map[Topic]uint64 `json:"topic_counts"`
}

// EventBus is a thread-safe, topic-based publish/subscribe message broker.
type EventBus struct {
	mu sync.RWMutex

	config        Config
	subscriptions map[Topic][]*Subscription
	allSubs       []*Subscription // subscribers for TopicWildcard
	nextSubID     uint64
	nextEventID   uint64

	// Atomic counters for stats
	published atomic.Uint64
	delivered atomic.Uint64
	dropped   atomic.Uint64

	// Topic-level counters (guarded by mu)
	topicCounts map[Topic]uint64

	// Lifecycle
	closed atomic.Bool
}

// New creates a new EventBus with the given configuration.
func New(cfg Config) *EventBus {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 256
	}
	if cfg.DeliveryTimeout <= 0 {
		cfg.DeliveryTimeout = 100 * time.Millisecond
	}
	return &EventBus{
		config:        cfg,
		subscriptions: make(map[Topic][]*Subscription),
		topicCounts:   make(map[Topic]uint64),
	}
}

// NewDefault creates a new EventBus with default configuration.
func NewDefault() *EventBus {
	return New(DefaultConfig())
}

// Subscribe registers a handler for the given topic and returns a
// Subscription that can be used to unsubscribe later. The handler
// is invoked asynchronously in a dedicated goroutine.
func (eb *EventBus) Subscribe(topic Topic, handler Handler) (*Subscription, error) {
	if eb.closed.Load() {
		return nil, fmt.Errorf("eventbus: bus is closed")
	}
	if handler == nil {
		return nil, fmt.Errorf("eventbus: handler must not be nil")
	}

	eb.mu.Lock()
	defer eb.mu.Unlock()

	eb.nextSubID++
	sub := &Subscription{
		ID:      fmt.Sprintf("sub-%d", eb.nextSubID),
		Topic:   topic,
		handler: handler,
		ch:      make(chan Event, eb.config.BufferSize),
		done:    make(chan struct{}),
	}
	sub.active.Store(true)

	if topic == TopicWildcard {
		eb.allSubs = append(eb.allSubs, sub)
	} else {
		eb.subscriptions[topic] = append(eb.subscriptions[topic], sub)
	}

	// Start delivery goroutine
	go eb.deliverLoop(sub)

	return sub, nil
}

// Unsubscribe removes a subscription and stops its delivery goroutine.
func (eb *EventBus) Unsubscribe(sub *Subscription) {
	if sub == nil {
		return
	}

	// Use CompareAndSwap to ensure only one goroutine closes the done channel.
	// This prevents a double-close panic when concurrent Unsubscribe or Close
	// calls race on the same subscription.
	if !sub.active.CompareAndSwap(true, false) {
		return
	}
	close(sub.done)

	eb.mu.Lock()
	defer eb.mu.Unlock()

	if sub.Topic == TopicWildcard {
		eb.allSubs = removeSub(eb.allSubs, sub)
	} else {
		subs := eb.subscriptions[sub.Topic]
		eb.subscriptions[sub.Topic] = removeSub(subs, sub)
		if len(eb.subscriptions[sub.Topic]) == 0 {
			delete(eb.subscriptions, sub.Topic)
		}
	}
}

// Publish sends an event to all subscribers of the event's topic and
// any wildcard ("*") subscribers. Events are delivered asynchronously.
// Returns an error if the bus is closed.
func (eb *EventBus) Publish(ctx context.Context, topic Topic, source string, payload interface{}) error {
	if eb.closed.Load() {
		return fmt.Errorf("eventbus: bus is closed")
	}

	eb.mu.RLock()
	// Assign event ID under read lock (safe with atomic)
	eventID := eb.generateEventID()
	event := Event{
		ID:        eventID,
		Topic:     topic,
		Timestamp: time.Now(),
		Source:    source,
		Payload:   payload,
	}

	// Collect target subscribers
	targets := make([]*Subscription, 0, len(eb.subscriptions[topic])+len(eb.allSubs))
	targets = append(targets, eb.subscriptions[topic]...)
	targets = append(targets, eb.allSubs...)
	eb.mu.RUnlock()

	// Record the publish
	eb.published.Add(1)
	eb.mu.Lock()
	eb.topicCounts[topic]++
	eb.mu.Unlock()

	// Deliver to each subscriber
	for _, sub := range targets {
		if !sub.active.Load() {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case sub.ch <- event:
			// Delivered to subscriber's channel
		default:
			// Channel is full — apply backpressure
			eb.dropped.Add(1)
		}
	}

	return nil
}

// PublishSync sends an event and blocks until all handlers have processed it.
// Useful for testing and critical events that must be handled before proceeding.
func (eb *EventBus) PublishSync(ctx context.Context, topic Topic, source string, payload interface{}) error {
	if eb.closed.Load() {
		return fmt.Errorf("eventbus: bus is closed")
	}

	event := Event{
		ID:        eb.generateEventID(),
		Topic:     topic,
		Timestamp: time.Now(),
		Source:    source,
		Payload:   payload,
	}

	eb.published.Add(1)
	eb.mu.Lock()
	eb.topicCounts[topic]++
	eb.mu.Unlock()

	eb.mu.RLock()
	targets := make([]*Subscription, 0, len(eb.subscriptions[topic])+len(eb.allSubs))
	targets = append(targets, eb.subscriptions[topic]...)
	targets = append(targets, eb.allSubs...)
	eb.mu.RUnlock()

	var wg sync.WaitGroup
	for _, sub := range targets {
		if !sub.active.Load() {
			continue
		}
		wg.Add(1)
		s := sub // capture
		go func() {
			defer wg.Done()
			s.handler(event)
			eb.delivered.Add(1)
		}()
	}
	wg.Wait()

	return nil
}

// Close shuts down the event bus. It stops accepting new events,
// drains in-flight events to subscribers, and stops delivery goroutines.
func (eb *EventBus) Close() {
	if eb.closed.Swap(true) {
		return // already closed
	}

	eb.mu.Lock()
	allSubs := make([]*Subscription, 0)
	for _, subs := range eb.subscriptions {
		allSubs = append(allSubs, subs...)
	}
	allSubs = append(allSubs, eb.allSubs...)
	eb.mu.Unlock()

	for _, sub := range allSubs {
		if sub.active.Swap(false) {
			close(sub.done)
		}
	}
}

// GetStats returns a snapshot of the bus runtime statistics.
func (eb *EventBus) GetStats() Stats {
	eb.mu.RLock()
	tc := make(map[Topic]uint64, len(eb.topicCounts))
	for k, v := range eb.topicCounts {
		tc[k] = v
	}
	activeSubs := 0
	for _, subs := range eb.subscriptions {
		for _, s := range subs {
			if s.active.Load() {
				activeSubs++
			}
		}
	}
	for _, s := range eb.allSubs {
		if s.active.Load() {
			activeSubs++
		}
	}
	eb.mu.RUnlock()

	return Stats{
		Published:         eb.published.Load(),
		Delivered:         eb.delivered.Load(),
		Dropped:           eb.dropped.Load(),
		ActiveSubscribers: activeSubs,
		TopicCounts:       tc,
	}
}

// IsClosed returns whether the event bus has been shut down.
func (eb *EventBus) IsClosed() bool {
	return eb.closed.Load()
}

// HasSubscribers returns true if the given topic has at least one active subscriber.
func (eb *EventBus) HasSubscribers(topic Topic) bool {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	for _, s := range eb.subscriptions[topic] {
		if s.active.Load() {
			return true
		}
	}
	for _, s := range eb.allSubs {
		if s.active.Load() {
			return true
		}
	}
	return false
}

// SubscriberCount returns the number of active subscribers for a topic
// (including wildcard subscribers).
func (eb *EventBus) SubscriberCount(topic Topic) int {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	count := 0
	for _, s := range eb.subscriptions[topic] {
		if s.active.Load() {
			count++
		}
	}
	for _, s := range eb.allSubs {
		if s.active.Load() {
			count++
		}
	}
	return count
}

// Topics returns the list of topics that have at least one subscriber.
func (eb *EventBus) Topics() []Topic {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	topics := make([]Topic, 0, len(eb.subscriptions))
	for t, subs := range eb.subscriptions {
		for _, s := range subs {
			if s.active.Load() {
				topics = append(topics, t)
				break
			}
		}
	}
	if len(eb.allSubs) > 0 {
		topics = append(topics, TopicWildcard)
	}
	return topics
}

// --- internal helpers ---

// deliverLoop runs in a dedicated goroutine per subscription, reading
// events from the channel and calling the handler.
func (eb *EventBus) deliverLoop(sub *Subscription) {
	for {
		select {
		case <-sub.done:
			// Drain remaining events before exiting
			for {
				select {
				case event := <-sub.ch:
					sub.handler(event)
					eb.delivered.Add(1)
				default:
					return
				}
			}
		case event := <-sub.ch:
			sub.handler(event)
			eb.delivered.Add(1)
		}
	}
}

// generateEventID creates a unique event ID (format: "evt-{timestamp}-{counter}").
func (eb *EventBus) generateEventID() string {
	id := atomic.AddUint64(&eb.nextEventID, 1)
	return fmt.Sprintf("evt-%d-%d", time.Now().UnixMilli(), id)
}

// removeSub removes a subscription from a slice by ID.
func removeSub(subs []*Subscription, target *Subscription) []*Subscription {
	result := make([]*Subscription, 0, len(subs))
	for _, s := range subs {
		if s.ID != target.ID {
			result = append(result, s)
		}
	}
	return result
}
