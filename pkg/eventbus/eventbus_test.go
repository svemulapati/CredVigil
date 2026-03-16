package eventbus

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitForCondition polls until cond returns true or timeout expires.
// Replaces time.Sleep-then-assert patterns to avoid flaky tests on slow machines.
func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("timed out waiting for condition: %s", msg)
}

// ─── Construction & Defaults ─────────────────────────────────────────────────

func TestNewDefault(t *testing.T) {
	bus := NewDefault()
	if bus == nil {
		t.Fatal("NewDefault returned nil")
	}
	if bus.IsClosed() {
		t.Error("new bus should not be closed")
	}
}

func TestNewWithConfig(t *testing.T) {
	cfg := Config{BufferSize: 64, DeliveryTimeout: 50 * time.Millisecond}
	bus := New(cfg)
	if bus.config.BufferSize != 64 {
		t.Errorf("expected buffer size 64, got %d", bus.config.BufferSize)
	}
	if bus.config.DeliveryTimeout != 50*time.Millisecond {
		t.Errorf("unexpected delivery timeout: %v", bus.config.DeliveryTimeout)
	}
}

func TestNewWithZeroBufferFallsBackToDefault(t *testing.T) {
	bus := New(Config{BufferSize: 0})
	if bus.config.BufferSize != 256 {
		t.Errorf("expected fallback buffer 256, got %d", bus.config.BufferSize)
	}
}

func TestNewWithNegativeTimeoutFallsBackToDefault(t *testing.T) {
	bus := New(Config{DeliveryTimeout: -1})
	if bus.config.DeliveryTimeout != 100*time.Millisecond {
		t.Errorf("expected fallback timeout 100ms, got %v", bus.config.DeliveryTimeout)
	}
}

// ─── Subscribe ───────────────────────────────────────────────────────────────

func TestSubscribeReturnsSubscription(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	sub, err := bus.Subscribe(TopicFileChanged, func(e Event) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sub == nil {
		t.Fatal("subscription is nil")
	}
	if sub.ID == "" {
		t.Error("subscription ID is empty")
	}
	if sub.Topic != TopicFileChanged {
		t.Errorf("expected topic %q, got %q", TopicFileChanged, sub.Topic)
	}
}

func TestSubscribeNilHandlerReturnsError(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	_, err := bus.Subscribe(TopicFileChanged, nil)
	if err == nil {
		t.Error("expected error for nil handler")
	}
}

func TestSubscribeOnClosedBusReturnsError(t *testing.T) {
	bus := NewDefault()
	bus.Close()

	_, err := bus.Subscribe(TopicFileChanged, func(e Event) {})
	if err == nil {
		t.Error("expected error subscribing to closed bus")
	}
}

func TestSubscribeMultipleToSameTopic(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	sub1, _ := bus.Subscribe(TopicScanStarted, func(e Event) {})
	sub2, _ := bus.Subscribe(TopicScanStarted, func(e Event) {})

	if sub1.ID == sub2.ID {
		t.Error("subscriptions should have unique IDs")
	}
	if bus.SubscriberCount(TopicScanStarted) != 2 {
		t.Errorf("expected 2 subscribers, got %d", bus.SubscriberCount(TopicScanStarted))
	}
}

// ─── Unsubscribe ─────────────────────────────────────────────────────────────

func TestUnsubscribeRemovesSubscriber(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	sub, _ := bus.Subscribe(TopicFileChanged, func(e Event) {})
	bus.Unsubscribe(sub)

	if bus.HasSubscribers(TopicFileChanged) {
		t.Error("topic should have no subscribers after unsubscribe")
	}
}

func TestUnsubscribeNilIsNoOp(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()
	bus.Unsubscribe(nil) // should not panic
}

func TestUnsubscribeIdempotent(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	sub, _ := bus.Subscribe(TopicFileChanged, func(e Event) {})
	bus.Unsubscribe(sub)
	bus.Unsubscribe(sub) // second call should be safe
}

func TestUnsubscribeWildcard(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	sub, _ := bus.Subscribe(TopicWildcard, func(e Event) {})
	bus.Unsubscribe(sub)

	if bus.HasSubscribers(TopicWildcard) {
		t.Error("wildcard should have no subscribers after unsubscribe")
	}
}

// ─── Publish & Delivery ──────────────────────────────────────────────────────

func TestPublishDeliversToSubscriber(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	received := make(chan Event, 1)
	bus.Subscribe(TopicFileChanged, func(e Event) {
		received <- e
	})

	err := bus.Publish(context.Background(), TopicFileChanged, "test", "payload")
	if err != nil {
		t.Fatalf("publish error: %v", err)
	}

	select {
	case e := <-received:
		if e.Topic != TopicFileChanged {
			t.Errorf("expected topic %q, got %q", TopicFileChanged, e.Topic)
		}
		if e.Source != "test" {
			t.Errorf("expected source 'test', got %q", e.Source)
		}
		if e.Payload != "payload" {
			t.Errorf("expected payload 'payload', got %v", e.Payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestPublishDeliversToMultipleSubscribers(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	var count atomic.Int32
	for i := 0; i < 3; i++ {
		bus.Subscribe(TopicScanCompleted, func(e Event) {
			count.Add(1)
		})
	}

	bus.Publish(context.Background(), TopicScanCompleted, "test", nil)

	waitForCondition(t, 2*time.Second, func() bool {
		return count.Load() == 3
	}, "expected 3 deliveries")

	if c := count.Load(); c != 3 {
		t.Errorf("expected 3 deliveries, got %d", c)
	}
}

func TestPublishOnClosedBusReturnsError(t *testing.T) {
	bus := NewDefault()
	bus.Close()

	err := bus.Publish(context.Background(), TopicFileChanged, "test", nil)
	if err == nil {
		t.Error("expected error publishing to closed bus")
	}
}

func TestPublishWithCancelledContext(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	// Fill the subscriber channel so publish blocks
	bus.Subscribe(TopicFileChanged, func(e Event) {
		time.Sleep(10 * time.Second) // slow handler
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := bus.Publish(ctx, TopicFileChanged, "test", nil)
	// May or may not error depending on timing — but should not hang
	_ = err
}

func TestPublishEventHasID(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	received := make(chan Event, 1)
	bus.Subscribe(TopicFileChanged, func(e Event) {
		received <- e
	})

	bus.Publish(context.Background(), TopicFileChanged, "test", nil)

	select {
	case e := <-received:
		if e.ID == "" {
			t.Error("event ID should not be empty")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
}

func TestPublishEventHasTimestamp(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	before := time.Now()
	received := make(chan Event, 1)
	bus.Subscribe(TopicFileChanged, func(e Event) {
		received <- e
	})

	bus.Publish(context.Background(), TopicFileChanged, "test", nil)

	select {
	case e := <-received:
		if e.Timestamp.Before(before) {
			t.Error("event timestamp should be >= test start time")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
}

// ─── Wildcard Subscription ───────────────────────────────────────────────────

func TestWildcardReceivesAllTopics(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	var received atomic.Int32
	bus.Subscribe(TopicWildcard, func(e Event) {
		received.Add(1)
	})

	topics := []Topic{TopicFileChanged, TopicScanStarted, TopicScanCompleted, TopicError}
	for _, topic := range topics {
		bus.Publish(context.Background(), topic, "test", nil)
	}

	waitForCondition(t, 2*time.Second, func() bool {
		return received.Load() == int32(len(topics))
	}, fmt.Sprintf("wildcard should receive %d events", len(topics)))

	if c := received.Load(); c != int32(len(topics)) {
		t.Errorf("wildcard should receive %d events, got %d", len(topics), c)
	}
}

func TestWildcardAndTopicSubscriberBothReceive(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	var topicCount, wildcardCount atomic.Int32
	bus.Subscribe(TopicFileChanged, func(e Event) {
		topicCount.Add(1)
	})
	bus.Subscribe(TopicWildcard, func(e Event) {
		wildcardCount.Add(1)
	})

	bus.Publish(context.Background(), TopicFileChanged, "test", nil)

	waitForCondition(t, 2*time.Second, func() bool {
		return topicCount.Load() == 1 && wildcardCount.Load() == 1
	}, "both topic and wildcard subscriber should receive 1 event")

	if topicCount.Load() != 1 {
		t.Errorf("topic subscriber should get 1 event, got %d", topicCount.Load())
	}
	if wildcardCount.Load() != 1 {
		t.Errorf("wildcard subscriber should get 1 event, got %d", wildcardCount.Load())
	}
}

func TestWildcardSubscriberCountIncludedInTopicCount(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	bus.Subscribe(TopicFileChanged, func(e Event) {})
	bus.Subscribe(TopicWildcard, func(e Event) {})

	if bus.SubscriberCount(TopicFileChanged) != 2 {
		t.Errorf("expected 2 (1 topic + 1 wildcard), got %d", bus.SubscriberCount(TopicFileChanged))
	}
}

// ─── PublishSync ─────────────────────────────────────────────────────────────

func TestPublishSyncDeliversSynchronously(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	var delivered atomic.Bool
	bus.Subscribe(TopicFileChanged, func(e Event) {
		time.Sleep(50 * time.Millisecond)
		delivered.Store(true)
	})

	err := bus.PublishSync(context.Background(), TopicFileChanged, "test", "sync-payload")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !delivered.Load() {
		t.Error("handler should have been called synchronously before PublishSync returned")
	}
}

func TestPublishSyncOnClosedBusReturnsError(t *testing.T) {
	bus := NewDefault()
	bus.Close()

	err := bus.PublishSync(context.Background(), TopicFileChanged, "test", nil)
	if err == nil {
		t.Error("expected error from PublishSync on closed bus")
	}
}

func TestPublishSyncToMultipleSubscribers(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	var count atomic.Int32
	for i := 0; i < 5; i++ {
		bus.Subscribe(TopicScanCompleted, func(e Event) {
			count.Add(1)
		})
	}

	bus.PublishSync(context.Background(), TopicScanCompleted, "test", nil)

	if c := count.Load(); c != 5 {
		t.Errorf("expected 5 sync deliveries, got %d", c)
	}
}

// ─── Stats ───────────────────────────────────────────────────────────────────

func TestStatsTrackPublishedEvents(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	bus.Subscribe(TopicFileChanged, func(e Event) {})

	for i := 0; i < 10; i++ {
		bus.Publish(context.Background(), TopicFileChanged, "test", nil)
	}

	waitForCondition(t, 2*time.Second, func() bool {
		return bus.GetStats().Published == 10
	}, "expected 10 published events in stats")

	stats := bus.GetStats()
	if stats.Published != 10 {
		t.Errorf("expected 10 published, got %d", stats.Published)
	}
}

func TestStatsTrackTopicCounts(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	bus.Subscribe(TopicFileChanged, func(e Event) {})
	bus.Subscribe(TopicScanStarted, func(e Event) {})

	bus.Publish(context.Background(), TopicFileChanged, "test", nil)
	bus.Publish(context.Background(), TopicFileChanged, "test", nil)
	bus.Publish(context.Background(), TopicScanStarted, "test", nil)

	waitForCondition(t, 2*time.Second, func() bool {
		s := bus.GetStats()
		return s.TopicCounts[TopicFileChanged] == 2 && s.TopicCounts[TopicScanStarted] == 1
	}, "expected topic counts to reflect published events")

	stats := bus.GetStats()
	if stats.TopicCounts[TopicFileChanged] != 2 {
		t.Errorf("expected 2 for file.changed, got %d", stats.TopicCounts[TopicFileChanged])
	}
	if stats.TopicCounts[TopicScanStarted] != 1 {
		t.Errorf("expected 1 for scan.started, got %d", stats.TopicCounts[TopicScanStarted])
	}
}

// ─── HasSubscribers ──────────────────────────────────────────────────────────

func TestHasSubscribersReturnsTrueWhenPresent(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	bus.Subscribe(TopicFileChanged, func(e Event) {})

	if !bus.HasSubscribers(TopicFileChanged) {
		t.Error("should have subscribers")
	}
}

func TestHasSubscribersReturnsFalseWhenEmpty(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	if bus.HasSubscribers(TopicFileChanged) {
		t.Error("should not have subscribers")
	}
}

// ─── Topics ──────────────────────────────────────────────────────────────────

func TestTopicsReturnsActiveTopics(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	bus.Subscribe(TopicFileChanged, func(e Event) {})
	bus.Subscribe(TopicScanStarted, func(e Event) {})
	bus.Subscribe(TopicWildcard, func(e Event) {})

	topics := bus.Topics()
	if len(topics) < 3 {
		t.Errorf("expected at least 3 topics, got %d: %v", len(topics), topics)
	}
}

// ─── Close ───────────────────────────────────────────────────────────────────

func TestCloseMarksAsClosed(t *testing.T) {
	bus := NewDefault()
	bus.Close()

	if !bus.IsClosed() {
		t.Error("bus should be closed after Close()")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	bus := NewDefault()
	bus.Close()
	bus.Close() // should not panic
}

func TestCloseStopsDelivery(t *testing.T) {
	bus := NewDefault()

	var count atomic.Int32
	bus.Subscribe(TopicFileChanged, func(e Event) {
		count.Add(1)
	})

	bus.Close()
	time.Sleep(50 * time.Millisecond)

	// Publishing after close should fail
	err := bus.Publish(context.Background(), TopicFileChanged, "test", nil)
	if err == nil {
		t.Error("expected error publishing after close")
	}
}

// ─── Event Model ─────────────────────────────────────────────────────────────

func TestEventFieldsPopulated(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	received := make(chan Event, 1)
	bus.Subscribe(TopicFindingDetected, func(e Event) {
		received <- e
	})

	type findingPayload struct {
		FilePath string
		RuleID   string
	}
	payload := findingPayload{FilePath: "/app/config.env", RuleID: "aws-secret"}

	bus.Publish(context.Background(), TopicFindingDetected, "detector", payload)

	select {
	case e := <-received:
		if e.Topic != TopicFindingDetected {
			t.Errorf("wrong topic: %q", e.Topic)
		}
		if e.Source != "detector" {
			t.Errorf("wrong source: %q", e.Source)
		}
		p, ok := e.Payload.(findingPayload)
		if !ok {
			t.Fatal("payload type assertion failed")
		}
		if p.FilePath != "/app/config.env" {
			t.Errorf("wrong file path: %q", p.FilePath)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
}

// ─── Topic Constants ─────────────────────────────────────────────────────────

func TestTopicConstants(t *testing.T) {
	expected := map[Topic]string{
		TopicFileChanged:      "file.changed",
		TopicScanStarted:      "scan.started",
		TopicScanCompleted:    "scan.completed",
		TopicFindingDetected:  "finding.detected",
		TopicFindingProcessed: "finding.processed",
		TopicGitScanStarted:   "git.scan.started",
		TopicGitScanCompleted: "git.scan.completed",
		TopicGitCommitScanned: "git.commit.scanned",
		TopicError:            "error",
		TopicWildcard:         "*",
	}
	for topic, want := range expected {
		if string(topic) != want {
			t.Errorf("Topic %q != expected %q", topic, want)
		}
	}
}

// ─── Concurrency Safety ─────────────────────────────────────────────────────

func TestConcurrentSubscribeAndPublish(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	var wg sync.WaitGroup
	ctx := context.Background()

	// Concurrent subscribes
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bus.Subscribe(TopicFileChanged, func(e Event) {})
		}()
	}

	// Concurrent publishes
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			bus.Publish(ctx, TopicFileChanged, "test", id)
		}(i)
	}

	wg.Wait()
	time.Sleep(100 * time.Millisecond)
}

func TestConcurrentUnsubscribe(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	subs := make([]*Subscription, 20)
	for i := 0; i < 20; i++ {
		subs[i], _ = bus.Subscribe(TopicScanCompleted, func(e Event) {})
	}

	var wg sync.WaitGroup
	for _, sub := range subs {
		wg.Add(1)
		s := sub
		go func() {
			defer wg.Done()
			bus.Unsubscribe(s)
		}()
	}
	wg.Wait()

	if bus.HasSubscribers(TopicScanCompleted) {
		t.Error("all subscribers should be removed")
	}
}

func TestConcurrentPublishAndClose(t *testing.T) {
	bus := NewDefault()

	bus.Subscribe(TopicFileChanged, func(e Event) {
		time.Sleep(time.Millisecond)
	})

	var wg sync.WaitGroup
	ctx := context.Background()

	// Publish rapidly
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bus.Publish(ctx, TopicFileChanged, "test", nil)
		}()
	}

	// Close mid-stream
	time.Sleep(5 * time.Millisecond)
	bus.Close()

	wg.Wait() // should not hang or panic
}

// ─── Integration Scenarios ───────────────────────────────────────────────────

func TestIntegration_FileWatcherToDetection(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	// Simulate: watcher publishes file.changed → detection subscriber picks it up
	scanTriggered := make(chan string, 1)

	bus.Subscribe(TopicFileChanged, func(e Event) {
		if path, ok := e.Payload.(string); ok {
			scanTriggered <- path
		}
	})

	// Watcher publishes
	bus.Publish(context.Background(), TopicFileChanged, "watcher", "/app/config.env")

	select {
	case path := <-scanTriggered:
		if path != "/app/config.env" {
			t.Errorf("expected /app/config.env, got %q", path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("detection was not triggered by file change event")
	}
}

func TestIntegration_AuditLogSubscriber(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	// Wildcard subscriber logs all events (audit trail)
	var auditLog []Event
	var mu sync.Mutex

	bus.Subscribe(TopicWildcard, func(e Event) {
		mu.Lock()
		auditLog = append(auditLog, e)
		mu.Unlock()
	})

	// Various components publish
	bus.Publish(context.Background(), TopicScanStarted, "cli", nil)
	bus.Publish(context.Background(), TopicFindingDetected, "detector", "aws-key")
	bus.Publish(context.Background(), TopicScanCompleted, "cli", nil)

	waitForCondition(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(auditLog) == 3
	}, "audit log should have 3 entries")

	mu.Lock()
	defer mu.Unlock()
	if len(auditLog) != 3 {
		t.Errorf("audit log should have 3 entries, got %d", len(auditLog))
	}
}

func TestIntegration_GitScanEventChain(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	events := make(chan Topic, 10)

	bus.Subscribe(TopicGitScanStarted, func(e Event) {
		events <- e.Topic
	})
	bus.Subscribe(TopicGitCommitScanned, func(e Event) {
		events <- e.Topic
	})
	bus.Subscribe(TopicGitScanCompleted, func(e Event) {
		events <- e.Topic
	})

	// Simulate git scan lifecycle
	ctx := context.Background()
	bus.Publish(ctx, TopicGitScanStarted, "git-scanner", nil)
	bus.Publish(ctx, TopicGitCommitScanned, "git-scanner", "commit-abc")
	bus.Publish(ctx, TopicGitCommitScanned, "git-scanner", "commit-def")
	bus.Publish(ctx, TopicGitScanCompleted, "git-scanner", nil)

	waitForCondition(t, 2*time.Second, func() bool {
		return len(events) == 4
	}, "expected 4 events in chain")

	if len(events) != 4 {
		t.Errorf("expected 4 events in chain, got %d", len(events))
	}
}

// ─── Edge Cases ──────────────────────────────────────────────────────────────

func TestPublishToTopicWithNoSubscribers(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	// Should not panic or error
	err := bus.Publish(context.Background(), TopicFileChanged, "test", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSubscribeToCustomTopic(t *testing.T) {
	bus := NewDefault()
	defer bus.Close()

	received := make(chan Event, 1)
	customTopic := Topic("custom.alert")

	bus.Subscribe(customTopic, func(e Event) {
		received <- e
	})
	bus.Publish(context.Background(), customTopic, "test", "custom-data")

	select {
	case e := <-received:
		if e.Topic != customTopic {
			t.Errorf("expected topic %q, got %q", customTopic, e.Topic)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
}

// ─── Benchmarks ──────────────────────────────────────────────────────────────

func BenchmarkPublish(b *testing.B) {
	bus := NewDefault()
	defer bus.Close()

	bus.Subscribe(TopicFileChanged, func(e Event) {})
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bus.Publish(ctx, TopicFileChanged, "bench", i)
	}
}

func BenchmarkPublishSync(b *testing.B) {
	bus := NewDefault()
	defer bus.Close()

	bus.Subscribe(TopicFileChanged, func(e Event) {})
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bus.PublishSync(ctx, TopicFileChanged, "bench", i)
	}
}

func BenchmarkSubscribeUnsubscribe(b *testing.B) {
	bus := NewDefault()
	defer bus.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sub, _ := bus.Subscribe(TopicFileChanged, func(e Event) {})
		bus.Unsubscribe(sub)
	}
}

func BenchmarkPublishFanOut(b *testing.B) {
	bus := NewDefault()
	defer bus.Close()

	for i := 0; i < 100; i++ {
		bus.Subscribe(TopicFileChanged, func(e Event) {})
	}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bus.Publish(ctx, TopicFileChanged, "bench", i)
	}
}

func BenchmarkPublishWithPayload(b *testing.B) {
	bus := NewDefault()
	defer bus.Close()

	type payload struct {
		Path   string
		RuleID string
		Score  float64
	}

	bus.Subscribe(TopicFindingDetected, func(e Event) {})
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bus.Publish(ctx, TopicFindingDetected, "bench", payload{
			Path:   fmt.Sprintf("/file-%d.go", i),
			RuleID: "aws-key",
			Score:  0.95,
		})
	}
}
