package language

import (
	"fmt"
	"unicode"
)

// CheckEnglish verifies that a log message contains only characters from the
// Latin / ASCII repertoire (letters, digits, whitespace, common punctuation).
//
// Non-Latin scripts such as Cyrillic, Chinese, Arabic etc. are rejected.
// This keeps log output machine-parseable and avoids encoding issues when
// logs are shipped to external aggregators that may not be UTF-8-aware.
func CheckEnglish(msg string) string {
	for _, r := range msg {
		// Allow ASCII printable characters – letters, digits, punctuation,
		// whitespace – everything in the Bahttps://gitlab.megotours.kz/mego.tours/backend_v2/core/-/merge_requests/54sic Latin block (U+0000–U+007F).
		if r <= unicode.MaxASCII {
			continue
		}

		// Allow a small subset of common Latin-Extended characters used in
		// English technical writing (e.g. en-dash U+2013, ellipsis U+2026).
		// Everything else is considered non-English.
		if isAllowedNonASCII(r) {
			continue
		}

		// Collect the script name for a more helpful diagnostic message.
		script := scriptName(r)
		return fmt.Sprintf(
			"log message contains non-English characters (%s script, rune %q)",
			script,
			r,
		)
	}
	return ""
}

// isAllowedNonASCII returns true for a small set of non-ASCII runes that are
// acceptable in English-language technical log messages.
func isAllowedNonASCII(r rune) bool {
	switch r {
	case '\u2013', // en-dash
		'\u2014',           // em-dash
		'\u2018', '\u2019', // curly single quotes
		'\u201C', '\u201D', // curly double quotes
		'\u2026': // ellipsis
		return true
	}
	return false
}

// scriptName returns a human-readable Unicode script name for the given rune.
// This is a best-effort categorisation for diagnostic messages only.
func scriptName(r rune) string {
	switch {
	case r >= 0x0400 && r <= 0x04FF:
		return "Cyrillic"
	case r >= 0x4E00 && r <= 0x9FFF:
		return "CJK"
	case r >= 0x0600 && r <= 0x06FF:
		return "Arabic"
	case r >= 0x0900 && r <= 0x097F:
		return "Devanagari"
	case r >= 0x1F300 && r <= 0x1FAFF:
		return "Emoji"
	default:
		return "non-Latin"
	}
}
