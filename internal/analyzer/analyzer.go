// Package analyzer implements the core go/analysis pass for loglinter.
//
// It walks every call expression in a package, identifies calls to supported
// logging libraries, extracts the message argument and runs the configured
// rule set against it.
//
// Supported loggers
//   - log/slog  – Info, Warn, Error, Debug (and their context variants InfoCtx etc.)
//   - go.uber.org/zap – Info, Warn, Error, Debug, Fatal, Panic (sugar and non-sugar)
//   - standard library log – Print, Printf, Println, Fatal*, Panic*
package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"

	"github.com/Wladim1r/loglinter/internal/config"
	"github.com/Wladim1r/loglinter/internal/rules"
)

// NewAnalyzer constructs an analysis.Analyzer using the given configuration.
// Passing nil uses DefaultConfig().
func NewAnalyzer(cfg *config.Config) *analysis.Analyzer {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	// Capture cfg in the closure so each Analyzer instance can have its own
	// configuration – important for tests that create multiple analyzers.
	run := func(pass *analysis.Pass) (interface{}, error) {
		return runPass(pass, cfg)
	}

	return newBaseAnalyzer(run)
}

// Analyzer is the default singleton analyzer used by the golangci-lint plugin
// and by default configuration. It reads configuration from .loglinter.yaml in
// the current working directory.
var Analyzer = NewAnalyzer(loadConfigOrDefault())

// NewFlagConfiguredAnalyzer constructs an Analyzer that loads configuration
// from the provided path flag. It is intended for use by the standalone
// command, so that flags (including -config and -fix) are owned by
// singlechecker.Main.
//
// configPath is expected to be a flag.String variable from the main package.
// The value is read after flags have been parsed.
func NewFlagConfiguredAnalyzer(configPath *string) *analysis.Analyzer {
	run := func(pass *analysis.Pass) (interface{}, error) {
		path := ".loglinter.yaml"
		if configPath != nil && *configPath != "" {
			path = *configPath
		}
		cfg, err := config.Load(path)
		if err != nil {
			// Fall back to defaults if config cannot be loaded; this matches
			// the behaviour of loadConfigOrDefault used for the plugin.
			cfg = config.DefaultConfig()
		}
		return runPass(pass, cfg)
	}
	return newBaseAnalyzer(run)
}

// loadConfigOrDefault attempts to load .loglinter.yaml; falls back to defaults.
func loadConfigOrDefault() *config.Config {
	cfg, err := config.Load(".loglinter.yaml")
	if err != nil {
		// Non-fatal: fall back to defaults and let the user know via stderr.
		return config.DefaultConfig()
	}
	return cfg
}

// newBaseAnalyzer builds the common Analyzer struct used by all constructors.
func newBaseAnalyzer(run func(*analysis.Pass) (interface{}, error)) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     "loglinter",
		Doc:      "checks log messages for style, language, special characters and sensitive data",
		Requires: []*analysis.Analyzer{inspect.Analyzer},
		Run:      run,
	}
}

// ---------------------------------------------------------------------------
// Internal pass implementation
// ---------------------------------------------------------------------------

// logCall describes a call to a logging function that we want to analyse.
type logCall struct {
	// pos is the source position of the call expression (for diagnostics).
	pos token.Pos
	// msgArg is the AST node of the message argument.
	msgArg ast.Expr
	// msgLiteral is the resolved string value of the message, or "" when the
	// message is a non-constant expression.
	msgLiteral string
	// fullExpr is the full source text of the message argument, used for the
	// sensitive-data check so we can inspect variable names.
	fullExpr string
}

// runPass is the main analysis function invoked by go/analysis.
func runPass(pass *analysis.Pass, cfg *config.Config) (interface{}, error) {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	// We only care about call expressions.
	nodeFilter := []ast.Node{
		(*ast.CallExpr)(nil),
	}

	insp.Preorder(nodeFilter, func(n ast.Node) {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return
		}

		lc, ok := extractLogCall(pass, call)
		if !ok {
			return
		}

		analyseCall(pass, cfg, lc)
	})

	return nil, nil
}

// extractLogCall returns a logCall descriptor if the call expression is a
// supported logging call, otherwise returns (_, false).
func extractLogCall(pass *analysis.Pass, call *ast.CallExpr) (logCall, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return logCall{}, false
	}

	if !isSupportedLogMethod(pass, sel) {
		return logCall{}, false
	}

	// Determine the index of the message argument for this logger family.
	msgIdx := messageArgIndex(pass, sel, call.Args)
	if msgIdx < 0 || msgIdx >= len(call.Args) {
		return logCall{}, false
	}

	msgArg := call.Args[msgIdx]
	literal, fullExpr := extractStringValue(pass, msgArg)

	return logCall{
		pos:        call.Pos(),
		msgArg:     msgArg,
		msgLiteral: literal,
		fullExpr:   fullExpr,
	}, true
}

// isSupportedLogMethod returns true when sel refers to a method of one of the
// supported logging packages.
func isSupportedLogMethod(pass *analysis.Pass, sel *ast.SelectorExpr) bool {
	method := sel.Sel.Name
	if !isLogMethod(method) {
		return false
	}

	// Resolve the receiver type / package.
	obj, ok := pass.TypesInfo.Uses[sel.Sel]
	if !ok {
		return false
	}

	pkg := pkgPathOf(obj)
	return isSupportedPackage(pkg)
}

// isLogMethod returns true for method names that are conventional log call
// entry points across our supported loggers.
func isLogMethod(name string) bool {
	switch name {
	case
		// slog and zap shared names
		"Info", "Warn", "Error", "Debug",
		// zap additional
		"Fatal", "Panic", "DPanic",
		// slog context variants
		"InfoCtx", "WarnCtx", "ErrorCtx", "DebugCtx",
		"InfoContext", "WarnContext", "ErrorContext", "DebugContext",
		// log stdlib
		"Print", "Printf", "Println",
		"Fatalf", "Fatalln",
		"Panicf", "Panicln":
		return true
	}
	return false
}

// supportedPkgPrefixes is the set of import path prefixes that we recognise
// as logging libraries.
var supportedPkgPrefixes = []string{
	"log/slog",
	"go.uber.org/zap",
	"go.uber.org/zap/zaptest",
	"log", // standard library log (exact match handled in isSupportedPackage)
}

func isSupportedPackage(pkgPath string) bool {
	for _, prefix := range supportedPkgPrefixes {
		if pkgPath == prefix || strings.HasPrefix(pkgPath, prefix+"/") {
			return true
		}
	}
	// Match the standard "log" package exactly (avoid matching e.g. "logrus").
	return pkgPath == "log"
}

// pkgPathOf extracts the import path of the package that declares obj.
func pkgPathOf(obj types.Object) string {
	if obj == nil || obj.Pkg() == nil {
		return ""
	}
	return obj.Pkg().Path()
}

// messageArgIndex returns the 0-based index of the message string argument for
// the given logging call.
//
//   - For slog and standard log, the message is always argument 0.
//   - For zap sugar (Infow, Warnw etc.) and non-sugar (Info(msg, fields...)) the
//     message is also argument 0.
//   - For zap's Infof/Warnf etc. the message is argument 0 (format string).
func messageArgIndex(pass *analysis.Pass, sel *ast.SelectorExpr, args []ast.Expr) int {
	// All supported methods use argument index 0 for the message.
	// This may need extending if a future logger family differs.
	_ = pass
	_ = sel
	_ = args
	return 0
}

// extractStringValue attempts to resolve a string constant from the expression.
// It also returns a full-expression string for the sensitive check.
func extractStringValue(pass *analysis.Pass, expr ast.Expr) (literal, fullExpr string) {
	fullExpr = exprToString(pass, expr)

	// Traverse the expression tree collecting string literals so we can
	// reconstruct the concatenated value as accurately as possible.
	var parts []string
	collectStringParts(pass, expr, &parts)
	literal = strings.Join(parts, "")

	return literal, fullExpr
}

// collectStringParts recursively collects string literal values from an
// expression, following binary + concatenation chains.
func collectStringParts(pass *analysis.Pass, expr ast.Expr, parts *[]string) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			// Unquote the raw string literal.
			s := strings.Trim(e.Value, "`")
			s = strings.TrimPrefix(s, "\"")
			s = strings.TrimSuffix(s, "\"")
			// Handle simple escape sequences.
			s = strings.ReplaceAll(s, `\"`, `"`)
			s = strings.ReplaceAll(s, `\\`, `\`)
			s = strings.ReplaceAll(s, `\n`, "\n")
			s = strings.ReplaceAll(s, `\t`, "\t")
			*parts = append(*parts, s)
		}

	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			collectStringParts(pass, e.X, parts)
			collectStringParts(pass, e.Y, parts)
		}

	case *ast.Ident:
		// If the identifier is a typed constant we can evaluate it.
		if obj, ok := pass.TypesInfo.Uses[e]; ok {
			if c, ok := obj.(*types.Const); ok {
				val := c.Val().String()
				val = strings.Trim(val, `"`)
				*parts = append(*parts, val)
			}
		}
		// Otherwise the variable name itself is useful for sensitive-data checks
		// – we leave it to exprToString to capture the raw identifier text.

	case *ast.ParenExpr:
		collectStringParts(pass, e.X, parts)
	}
}

// exprToString returns a textual representation of the expression node,
// suitable for use in diagnostics and the sensitive-data keyword search.
func exprToString(pass *analysis.Pass, expr ast.Expr) string {
	if expr == nil {
		return ""
	}
	// Use the file set to reconstruct the source text when possible.
	fset := pass.Fset
	start := fset.Position(expr.Pos())
	end := fset.Position(expr.End())

	// Try to read from the source file.
	if start.IsValid() && end.IsValid() && start.Filename == end.Filename {
		src := sourceFragment(pass, start.Filename, expr.Pos(), expr.End())
		if src != "" {
			return src
		}
	}

	// Fallback: walk the AST and concatenate what we can.
	var sb strings.Builder
	ast.Inspect(expr, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok {
			sb.WriteString(lit.Value)
		} else if id, ok := n.(*ast.Ident); ok {
			sb.WriteString(id.Name)
		}
		return true
	})
	return sb.String()
}

// sourceFragment returns the raw source bytes for the given position range.
func sourceFragment(pass *analysis.Pass, filename string, from, to token.Pos) string {
	// Iterate over all files in the pass to find matching source.
	for _, f := range pass.Files {
		pos := pass.Fset.Position(f.Pos())
		if filepath.Clean(pos.Filename) != filepath.Clean(filename) {
			continue
		}
		// Re-read the file from the token.File.
		tokenFile := pass.Fset.File(f.Pos())
		if tokenFile == nil {
			return ""
		}
		start := tokenFile.Offset(from)
		end := tokenFile.Offset(to)
		// We need the raw source bytes – access them through the AST file's
		// comment map or directly via the file content if available.
		// Since go/analysis doesn't directly expose raw bytes we reconstruct
		// from the AST as a best-effort approach.
		_ = start
		_ = end
		return ""
	}
	return ""
}

// ---------------------------------------------------------------------------
// Rule execution
// ---------------------------------------------------------------------------

// analyseCall runs all enabled rules against the extracted log call and
// reports diagnostics via pass.Report.
func analyseCall(pass *analysis.Pass, cfg *config.Config, lc logCall) {
	msg := lc.msgLiteral

	// Rule 1: lowercase first letter.
	if cfg.IsRuleEnabled(config.RuleLowercase) {
		if diag := rules.CheckLowercase(msg); diag != "" {
			d := analysis.Diagnostic{
				Pos:     lc.msgArg.Pos(),
				End:     lc.msgArg.End(),
				Message: diag,
				// SuggestedFix: auto-lowercase the first letter.
				SuggestedFixes: suggestLowercaseFix(pass, lc, msg),
			}
			reportDiagnostic(pass, d)
		}
	}

	// Rule 2: English-only characters.
	if cfg.IsRuleEnabled(config.RuleEnglish) {
		if diag := rules.CheckEnglish(msg); diag != "" {
			d := analysis.Diagnostic{
				Pos:     lc.msgArg.Pos(),
				End:     lc.msgArg.End(),
				Message: diag,
			}
			reportDiagnostic(pass, d)
		}
	}

	// Rule 3: No special characters or emoji.
	if cfg.IsRuleEnabled(config.RuleSpecial) {
		if diag := rules.CheckSpecialChars(msg, cfg.AllowedSpecialChars); diag != "" {
			d := analysis.Diagnostic{
				Pos:            lc.msgArg.Pos(),
				End:            lc.msgArg.End(),
				Message:        diag,
				SuggestedFixes: suggestSpecialFix(pass, lc, msg, cfg.AllowedSpecialChars),
			}
			reportDiagnostic(pass, d)
		}
	}

	// Rule 4: No sensitive data.
	if cfg.IsRuleEnabled(config.RuleSensitive) {
		if diag := rules.CheckSensitive(msg, lc.fullExpr, cfg.SensitiveKeywords); diag != "" {
			d := analysis.Diagnostic{
				Pos:     lc.msgArg.Pos(),
				End:     lc.msgArg.End(),
				Message: diag,
			}
			reportDiagnostic(pass, d)
		}
	}
}

// ---------------------------------------------------------------------------
// SuggestedFixes (bonus: auto-correction)
// ---------------------------------------------------------------------------

// suggestLowercaseFix returns a SuggestedFix that lowercases the first rune of
// the string literal if the message argument is a simple string literal.
func suggestLowercaseFix(pass *analysis.Pass, lc logCall, msg string) []analysis.SuggestedFix {
	if msg == "" {
		return nil
	}

	// Only generate an auto-fix for simple string literals – we don't want to
	// rewrite complex concatenation expressions automatically.
	lit, ok := lc.msgArg.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return nil
	}

	// Determine the fixed string value.
	runes := []rune(msg)
	if len(runes) == 0 {
		return nil
	}

	fixed := string(append([]rune{lowerRune(runes[0])}, runes[1:]...))
	if fixed == msg {
		return nil // already lowercase, no fix needed
	}

	// Reconstruct the quoted literal.
	quote := string(lit.Value[0]) // " or `
	fixedLit := quote + fixed + quote

	return []analysis.SuggestedFix{
		{
			Message: "lowercase first letter of log message",
			TextEdits: []analysis.TextEdit{
				{
					Pos:     lit.Pos(),
					End:     lit.End(),
					NewText: []byte(fixedLit),
				},
			},
		},
	}
}

// lowerRune returns the lowercase version of r.
func lowerRune(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}

// reportDiagnostic prints a concise summary (file, line, column, status) and
// then forwards the diagnostic to the analysis framework.
func reportDiagnostic(pass *analysis.Pass, d analysis.Diagnostic) {
	pos := pass.Fset.Position(d.Pos)
	status := "ERROR"
	if len(d.SuggestedFixes) > 0 {
		status = "FIX"
	}

	// Example:
	//   loglinter: FIX /path/to/file.go:12:34: lowercase first letter of log message
	fmt.Fprintf(
		os.Stderr,
		"loglinter: %s %s:%d:%d: %s\n",
		status,
		pos.Filename,
		pos.Line,
		pos.Column,
		d.Message,
	)

	pass.Report(d)
}

// ---------------------------------------------------------------------------
// Auto-fix for special characters / emoji
// ---------------------------------------------------------------------------

const defaultForbiddenASCII = "!@#$%^&*+=|\\<>?`~;'\""

// cleanSpecialMessage removes emoji and noisy punctuation/symbols from msg,
// keeping letters, digits, whitespace and a small set of safe ASCII
// punctuation (plus any characters explicitly whitelisted via allowedExtra).
func cleanSpecialMessage(msg, allowedExtra string) string {
	if msg == "" {
		return msg
	}

	allowed := make(map[rune]struct{}, len(allowedExtra))
	for _, r := range allowedExtra {
		allowed[r] = struct{}{}
	}

	var b strings.Builder
	b.Grow(len(msg))

	for _, r := range msg {
		// Drop all non-ASCII runes – this covers emoji and other
		// pictographic symbols in a simple, conservative way.
		if r > unicode.MaxASCII {
			continue
		}

		if _, ok := allowed[r]; ok {
			b.WriteRune(r)
			continue
		}

		// Remove explicitly forbidden ASCII punctuation.
		if strings.ContainsRune(defaultForbiddenASCII, r) {
			continue
		}

		// Keep common "safe" punctuation used in normal text and paths.
		switch r {
		case '-', '_', '/', ':', '.', ',', ' ':
			b.WriteRune(r)
			continue
		}

		// For remaining ASCII runes, drop those classified as punctuation or
		// symbols to reduce log noise.
		if unicode.IsPunct(r) || unicode.IsSymbol(r) {
			continue
		}

		b.WriteRune(r)
	}

	return b.String()
}

// suggestSpecialFix constructs a SuggestedFix that removes emoji and
// disallowed special characters from simple string literals. For complex
// expressions (concatenations, variables, formatting) we skip auto-fix to
// avoid surprising rewrites.
func suggestSpecialFix(
	pass *analysis.Pass,
	lc logCall,
	msg, allowedExtra string,
) []analysis.SuggestedFix {
	if msg == "" {
		return nil
	}

	lit, ok := lc.msgArg.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return nil
	}

	fixed := cleanSpecialMessage(msg, allowedExtra)
	if fixed == msg {
		return nil
	}

	quote := string(lit.Value[0]) // " or `
	fixedLit := quote + fixed + quote

	return []analysis.SuggestedFix{
		{
			Message: "remove emoji and noisy special characters from log message",
			TextEdits: []analysis.TextEdit{
				{
					Pos:     lit.Pos(),
					End:     lit.End(),
					NewText: []byte(fixedLit),
				},
			},
		},
	}
}
