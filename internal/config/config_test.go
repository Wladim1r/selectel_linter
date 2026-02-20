package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Wladim1r/loglinter/internal/config"
)

func TestDefaultConfig(t *testing.T) {
	t.Parallel()
	cfg := config.DefaultConfig()

	for _, rule := range []string{
		config.RuleLowercase,
		config.RuleEnglish,
		config.RuleSpecial,
		config.RuleSensitive,
	} {
		if !cfg.IsRuleEnabled(rule) {
			t.Errorf("expected rule %q to be enabled by default", rule)
		}
	}

	if len(cfg.SensitiveKeywords) == 0 {
		t.Error("expected non-empty default sensitive keywords")
	}
}

func TestIsRuleEnabled_UnknownRule(t *testing.T) {
	t.Parallel()
	cfg := config.DefaultConfig()
	// Unknown rule names should default to enabled.
	if !cfg.IsRuleEnabled("nonexistent_rule") {
		t.Error("unknown rule should default to enabled")
	}
}

func TestLoad_NoFile(t *testing.T) {
	t.Parallel()
	// Point to a non-existent file – should return defaults without error.
	cfg, err := config.Load("/tmp/does_not_exist_loglinter.yaml")
	if err != nil {
		t.Fatalf("Load with missing file returned error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestLoad_ValidYAML(t *testing.T) {
	t.Parallel()

	yaml := `
rules:
  sensitive: false
  lowercase: true
sensitive_keywords:
  - my_secret
allowed_special_chars: "!"
`
	f := writeTempFile(t, yaml)

	cfg, err := config.Load(f)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.IsRuleEnabled(config.RuleSensitive) {
		t.Error("expected sensitive rule to be disabled")
	}
	if !cfg.IsRuleEnabled(config.RuleLowercase) {
		t.Error("expected lowercase rule to be enabled")
	}

	found := false
	for _, kw := range cfg.SensitiveKeywords {
		if kw == "my_secret" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected custom keyword my_secret in config")
	}

	if cfg.AllowedSpecialChars != "!" {
		t.Errorf("expected AllowedSpecialChars to be !, got %q", cfg.AllowedSpecialChars)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	t.Parallel()
	f := writeTempFile(t, "rules: [invalid yaml }{")
	_, err := config.Load(f)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".loglinter.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writeTempFile: %v", err)
	}
	return path
}
