package analyzer_test

import (
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/Wladim1r/loglinter/internal/analyzer"
	"github.com/Wladim1r/loglinter/internal/config"
)

// testdataDir returns the absolute path to the testdata/src directory.
func testdataDir(t *testing.T) string {
	t.Helper()
	// analysistest.TestData() looks for a "testdata" dir relative to the
	// package being tested, which is internal/analyzer.
	//
	// analysistest.Run expects a directory that contains a "src" subdir.
	// So we pass the testdata root (which already contains "src/").
	return filepath.Clean(analysistest.TestData())
}

// TestAnalyzer_Lowercase runs the linter against testdata/src/lowercase and
// verifies that only the expected diagnostics are reported.
func TestAnalyzer_Lowercase(t *testing.T) {
	t.Parallel()
	cfg := config.DefaultConfig()
	// Disable all rules except lowercase so diagnostics are unambiguous.
	cfg.Rules[config.RuleEnglish] = false
	cfg.Rules[config.RuleSpecial] = false
	cfg.Rules[config.RuleSensitive] = false

	a := analyzer.NewAnalyzer(cfg)
	analysistest.Run(t, testdataDir(t), a, "lowercase")
}

// TestAnalyzer_English runs against testdata/src/language.
func TestAnalyzer_English(t *testing.T) {
	t.Parallel()
	cfg := config.DefaultConfig()
	cfg.Rules[config.RuleLowercase] = false
	cfg.Rules[config.RuleSpecial] = false
	cfg.Rules[config.RuleSensitive] = false

	a := analyzer.NewAnalyzer(cfg)
	analysistest.Run(t, testdataDir(t), a, "language")
}

// TestAnalyzer_Special runs against testdata/src/special.
func TestAnalyzer_Special(t *testing.T) {
	t.Parallel()
	cfg := config.DefaultConfig()
	cfg.Rules[config.RuleLowercase] = false
	cfg.Rules[config.RuleEnglish] = false
	cfg.Rules[config.RuleSensitive] = false

	a := analyzer.NewAnalyzer(cfg)
	analysistest.Run(t, testdataDir(t), a, "special")
}

// TestAnalyzer_Sensitive runs against testdata/src/sensitive.
func TestAnalyzer_Sensitive(t *testing.T) {
	t.Parallel()
	cfg := config.DefaultConfig()
	cfg.Rules[config.RuleLowercase] = false
	cfg.Rules[config.RuleEnglish] = false
	cfg.Rules[config.RuleSpecial] = false

	a := analyzer.NewAnalyzer(cfg)
	analysistest.Run(t, testdataDir(t), a, "sensitive")
}

// TestAnalyzer_AllRules verifies that all four rules fire together on the
// combined testdata/src/basic fixture.
func TestAnalyzer_AllRules(t *testing.T) {
	t.Parallel()
	a := analyzer.NewAnalyzer(config.DefaultConfig())
	analysistest.Run(t, testdataDir(t), a, "basic")
}
