// Package rules contains individual linting rules for log messages.
// Each rule is implemented as a self-contained function that accepts a
// message string and returns a diagnostic description when the rule is
// violated, or an empty string when the message is valid.
package lowercase

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// CheckLowercase verifies that a log message begins with a lower-case letter.
//
// Rationale: consistent lower-case openings make log streams easier to grep
// and parse – tools that capitalise log levels (INFO, ERROR) would otherwise
// produce mixed-case lines.
//
// Returns a non-empty diagnostic string on violation.
func CheckLowercase(msg string) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return ""
	}

	// Decode the first UTF-8 rune so we handle multi-byte characters correctly.
	r, _ := utf8.DecodeRuneInString(msg)
	if r == utf8.RuneError {
		return ""
	}

	if unicode.IsUpper(r) {
		return "log message should start with a lowercase letter"
	}
	return ""
}
