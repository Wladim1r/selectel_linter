// Package config provides configuration loading and validation for loglinter.
// Configuration can be supplied via a YAML file (e.g. .loglinter.yaml) or
// programmatically for use in tests.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Rule names used as keys in the Disabled / Enabled maps.
const (
	RuleLowercase = "lowercase"
	RuleEnglish   = "english"
	RuleSpecial   = "special"
	RuleSensitive = "sensitive"
)

// Config is the top-level configuration structure for loglinter.
type Config struct {
	// Rules allows selectively disabling individual rules.
	// Example YAML:
	//   rules:
	//     sensitive: false
	Rules map[string]bool `yaml:"rules"`

	// SensitiveKeywords extends (or overrides) the default list of keywords
	// that trigger the sensitive-data rule. Values are matched case-insensitively
	// as substrings of the log message or concatenated string arguments.
	// Example YAML:
	//   sensitive_keywords:
	//     - secret
	//     - private_key
	SensitiveKeywords []string `yaml:"sensitive_keywords"`

	// AllowedSpecialChars lists characters that should NOT be flagged by the
	// special-characters rule. Useful for allowing punctuation like colons.
	// Example YAML:
	//   allowed_special_chars: "-_"
	AllowedSpecialChars string `yaml:"allowed_special_chars"`
}

// DefaultConfig returns a configuration with all rules enabled and a
// sensible set of sensitive keywords.
func DefaultConfig() *Config {
	return &Config{
		Rules: map[string]bool{
			RuleLowercase: true,
			RuleEnglish:   true,
			RuleSpecial:   true,
			RuleSensitive: true,
		},
		SensitiveKeywords: defaultSensitiveKeywords(),
	}
}

// IsRuleEnabled reports whether the named rule should run.
// Unknown rule names default to enabled so that new rules are active by
// default even if the user has not updated their config file.
func (c *Config) IsRuleEnabled(name string) bool {
	if c.Rules == nil {
		return true
	}
	enabled, ok := c.Rules[name]
	if !ok {
		return true
	}
	return enabled
}

// Load reads a YAML config file from path and merges it on top of the
// default configuration. Missing fields keep their default values.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// No config file is perfectly fine – use defaults.
			return cfg, nil
		}
		return nil, fmt.Errorf("loglinter: reading config %q: %w", path, err)
	}

	// We unmarshal into a temporary struct so we can selectively merge only
	// the fields that were actually present in the file.
	var file struct {
		Rules               map[string]bool `yaml:"rules"`
		SensitiveKeywords   []string        `yaml:"sensitive_keywords"`
		AllowedSpecialChars string          `yaml:"allowed_special_chars"`
	}

	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("loglinter: parsing config %q: %w", path, err)
	}

	if file.Rules != nil {
		for k, v := range file.Rules {
			cfg.Rules[k] = v
		}
	}
	if len(file.SensitiveKeywords) > 0 {
		// Extend defaults with user-supplied keywords.
		cfg.SensitiveKeywords = append(cfg.SensitiveKeywords, file.SensitiveKeywords...)
	}
	if file.AllowedSpecialChars != "" {
		cfg.AllowedSpecialChars = file.AllowedSpecialChars
	}

	return cfg, nil
}

// defaultSensitiveKeywords returns the built-in list of keywords that
// indicate potentially sensitive information in a log message.
func defaultSensitiveKeywords() []string {
	return []string{
		"password",
		"passwd",
		"secret",
		"token",
		"api_key",
		"apikey",
		"auth",
		"credential",
		"private_key",
		"access_key",
		"session",
		"jwt",
		"bearer",
		"ssn",
		"credit_card",
	}
}
