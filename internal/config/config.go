// Package config holds application-level configuration for CredVigil.
package config

// AppConfig holds the overall application configuration.
type AppConfig struct {
	// Application name
	AppName string `json:"app_name" yaml:"app_name"`
	// Log level: debug, info, warn, error
	LogLevel string `json:"log_level" yaml:"log_level"`
	// Output format: text, json, sarif
	OutputFormat string `json:"output_format" yaml:"output_format"`
	// Detection engine settings
	Detection DetectionConfig `json:"detection" yaml:"detection"`
	// File scanning settings
	FileScanning FileScanningConfig `json:"file_scanning" yaml:"file_scanning"`
}

// DetectionConfig holds detection engine configuration.
type DetectionConfig struct {
	MinConfidence     float64  `json:"min_confidence" yaml:"min_confidence"`
	EnableEntropy     bool     `json:"enable_entropy" yaml:"enable_entropy"`
	EntropyMinLength  int      `json:"entropy_min_length" yaml:"entropy_min_length"`
	ContextLines      int      `json:"context_lines" yaml:"context_lines"`
	MaxFileSize       int64    `json:"max_file_size" yaml:"max_file_size"`
	ExcludeRuleIDs    []string `json:"exclude_rule_ids" yaml:"exclude_rule_ids"`
	AllowListPatterns []string `json:"allow_list_patterns" yaml:"allow_list_patterns"`
}

// FileScanningConfig holds file scanning configuration.
type FileScanningConfig struct {
	IncludeExtensions []string `json:"include_extensions" yaml:"include_extensions"`
	ExcludeExtensions []string `json:"exclude_extensions" yaml:"exclude_extensions"`
	ExcludeDirs       []string `json:"exclude_dirs" yaml:"exclude_dirs"`
	ExcludeFiles      []string `json:"exclude_files" yaml:"exclude_files"`
	Workers           int      `json:"workers" yaml:"workers"`
	FollowSymlinks    bool     `json:"follow_symlinks" yaml:"follow_symlinks"`
}

// DefaultAppConfig returns a default application configuration.
func DefaultAppConfig() AppConfig {
	return AppConfig{
		AppName:      "credvigil",
		LogLevel:     "info",
		OutputFormat: "text",
		Detection: DetectionConfig{
			MinConfidence:    0.3,
			EnableEntropy:    true,
			EntropyMinLength: 12,
			ContextLines:     2,
			MaxFileSize:      10 * 1024 * 1024,
		},
		FileScanning: FileScanningConfig{
			Workers: 4,
		},
	}
}
