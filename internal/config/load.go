package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ConfigFileNames are the file names auto-discovered at a scan root, in order
// of precedence. YAML is the mainstream convention; JSON is accepted too.
var ConfigFileNames = []string{
	".credvigil.yml",
	".credvigil.yaml",
	".credvigil.json",
}

// Load reads a config file (YAML or JSON, chosen by extension) and layers it
// over the defaults so unspecified fields keep their sensible values.
func Load(path string) (AppConfig, error) {
	cfg := DefaultAppConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	switch filepath.Ext(path) {
	case ".json":
		if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parse %s: %w", path, err)
		}
	default: // .yml, .yaml, or unspecified
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	return cfg, nil
}

// Discover looks for a config file in dir (or the directory containing dir if
// it is a file). It returns the loaded config and the path found, or ok=false
// when no config file exists.
func Discover(root string) (cfg AppConfig, path string, ok bool, err error) {
	dir := root
	if info, statErr := os.Stat(root); statErr == nil && !info.IsDir() {
		dir = filepath.Dir(root)
	}
	for _, name := range ConfigFileNames {
		candidate := filepath.Join(dir, name)
		if _, statErr := os.Stat(candidate); statErr == nil {
			c, loadErr := Load(candidate)
			return c, candidate, true, loadErr
		}
	}
	return DefaultAppConfig(), "", false, nil
}
