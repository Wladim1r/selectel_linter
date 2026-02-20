// Package plugin exposes loglinter as a golangci-lint custom linter plugin.
//
// To use loglinter with golangci-lint as a module plugin, add the following
// to your .golangci.yml:
//
//	linters-settings:
//	  custom:
//	    loglinter:
//	      path: /path/to/loglinter.so
//	      description: Checks log messages for style, language and sensitive data
//	      original-url: github.com/yourusername/loglinter
//
// Build the plugin shared object with:
//
//	go build -buildmode=plugin -o loglinter.so ./plugin/
//
// golangci-lint v1.x module plugin API requires a package-level variable
// named "AnalyzerPlugin" that implements the nolintlint interface, or more
// specifically the golangci-lint plugin interface which expects a function
// New(conf interface{}) ([]*analysis.Analyzer, error).
package main

import (
	"github.com/Wladim1r/loglinter/internal/analyzer"
	"github.com/Wladim1r/loglinter/internal/config"
	"golang.org/x/tools/go/analysis"
)

// AnalyzerPlugin is the symbol that golangci-lint looks for when loading a
// plugin via -buildmode=plugin.
// It must be named exactly "AnalyzerPlugin".
var AnalyzerPlugin analyzerPlugin //nolint:deadcode,unused // exported for plugin loader

type analyzerPlugin struct{}

// GetAnalyzers returns the list of analyzers provided by this plugin.
// golangci-lint calls this method after loading the plugin.
func (analyzerPlugin) GetAnalyzers() []*analysis.Analyzer {
	// Load configuration from the current working directory; fall back to
	// defaults if the file is absent or cannot be parsed.
	cfg, err := config.Load(".loglinter.yaml")
	if err != nil {
		cfg = config.DefaultConfig()
	}
	return []*analysis.Analyzer{analyzer.NewAnalyzer(cfg)}
}
