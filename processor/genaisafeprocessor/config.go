package genaisafeprocessor

// Config for the genaisafe processor.
type Config struct {
	Redact        RedactConfig        `mapstructure:"redact"`
	Metrics       MetricsConfig       `mapstructure:"metrics"`
	LoopDetection LoopDetectionConfig `mapstructure:"loop_detection"`
}

// RedactConfig controls PII redaction behavior.
type RedactConfig struct {
	// Mode: "hash_and_preview" keeps first N chars + hash, "full_hash" replaces entirely.
	Mode         string   `mapstructure:"mode"`
	PreviewChars int      `mapstructure:"preview_chars"`
	Salt         string   `mapstructure:"salt"`
	Keys         []string `mapstructure:"keys"`
	// DenylistRegex: patterns that trigger redaction regardless of key.
	DenylistRegex []string `mapstructure:"denylist_regex"`
}

// MetricsConfig controls token metrics emission.
type MetricsConfig struct {
	Enable bool `mapstructure:"enable"`
}

// LoopDetectionConfig detects repeated identical prompts.
type LoopDetectionConfig struct {
	Enable          bool `mapstructure:"enable"`
	RepeatThreshold int  `mapstructure:"repeat_threshold"`
}

func createDefaultConfig() *Config {
	return &Config{
		Redact: RedactConfig{
			Mode:         "hash_and_preview",
			PreviewChars: 48,
			Salt:         "air-default-salt",
			Keys: []string{
				"gen_ai.prompt",
				"gen_ai.completion",
				"llm.prompt",
				"llm.completion",
			},
			DenylistRegex: []string{
				`(?i)api[_-]?key`,
				`(?i)authorization`,
				`(?i)sk-[a-z0-9]{20,}`,
			},
		},
		Metrics: MetricsConfig{
			Enable: true,
		},
		LoopDetection: LoopDetectionConfig{
			Enable:          true,
			RepeatThreshold: 6,
		},
	}
}