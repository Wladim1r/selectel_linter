// Command loglinter is a standalone runner for the loglinter analysis pass.
//
// Usage:
//
//	loglinter [flags] [packages]
//
// Examples:
//
//	# Lint the current module
//	loglinter ./...
//
//	# Use a custom config file
//	loglinter -config /path/to/.loglinter.yaml ./...
//
//	# Apply auto-fixes (lowercase rule)
//	loglinter -fix ./...
package main

import (
	"flag"

	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/Wladim1r/loglinter/internal/analyzer"
)

var configPath = flag.String(
	"config",
	".loglinter.yaml",
	"path to loglinter YAML configuration file",
)

func main() {
	// singlechecker.Main owns flag parsing, including the built-in -fix flag.
	// We only declare -config here; its value is read inside the analyzer via
	// analyzer.NewFlagConfiguredAnalyzer.
	singlechecker.Main(analyzer.NewFlagConfiguredAnalyzer(configPath))
}
