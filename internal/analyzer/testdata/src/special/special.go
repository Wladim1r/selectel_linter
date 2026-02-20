package special

import (
	"fmt"
	"strings"
	"unicode"
)

// specialCharSet is the set of ASCII punctuation/symbol characters that are
// NOT allowed in log messages. Letters, digits and whitespace are always
// allowed; the characters below are the ones that make logs noisy and hard to
// parse reliably.
//
// Note: hyphen (-), underscore (_), slash (/), colon (:), dot (.) and
// comma (,) are intentionally NOT in this list because they appear
// legitimately in paths, identifiers and sentences.
const defaultForbiddenASCII = "!@#$%^&*+=|\\<>?`~;'\""

// CheckSpecialChars verifies that a log message does not contain special
// characters or emoji.
//
// allowedExtra is an optional string of additional characters that the caller
// considers safe (sourced from the user's config file). Any character present
// in allowedExtra is excluded from the check.
func CheckSpecialChars(msg, allowedExtra string) string {
	forbidden := buildForbiddenSet(allowedExtra)

	for i, r := range msg {
		_ = i

		// Emoji are encoded in Unicode ranges above U+1F000.
		// Also catch Miscellaneous Symbols (U+2600–U+26FF) and
		// Dingbats (U+2700–U+27BF).
		if isEmoji(r) {
			return fmt.Sprintf("log message contains emoji or special Unicode symbol (rune %q)", r)
		}

		// For ASCII punctuation, check against the forbidden set.
		if r <= unicode.MaxASCII && unicode.IsPunct(r) || unicode.IsSymbol(r) {
			if _, bad := forbidden[r]; bad {
				return fmt.Sprintf("log message contains forbidden special character %q", r)
			}
		}
	}

	// Detect repeated punctuation like "!!!" or "..." that pollutes log output.
	if diag := checkRepeatedPunctuation(msg); diag != "" {
		return diag
	}

	return ""
}

// buildForbiddenSet returns a set built from defaultForbiddenASCII minus any
// characters the user explicitly allows.
func buildForbiddenSet(allowedExtra string) map[rune]struct{} {
	allowed := make(map[rune]struct{}, len(allowedExtra))
	for _, r := range allowedExtra {
		allowed[r] = struct{}{}
	}

	set := make(map[rune]struct{}, len(defaultForbiddenASCII))
	for _, r := range defaultForbiddenASCII {
		if _, ok := allowed[r]; !ok {
			set[r] = struct{}{}
		}
	}
	return set
}

// isEmoji returns true for runes that are conventionally classified as emoji
// or pictographic symbols.
func isEmoji(r rune) bool {
	return unicode.Is(unicode.So, r) || // Other_Symbol – covers many emoji
		(r >= 0x1F300 && r <= 0x1FAFF) || // Misc Symbols and Pictographs, Emoji
		(r >= 0x2600 && r <= 0x27BF) || // Misc Symbols, Dingbats
		(r >= 0xFE00 && r <= 0xFE0F) // Variation Selectors
}

// checkRepeatedPunctuation detects patterns like "!!!" or "..." which indicate
// emphasis that has no place in structured log messages.
func checkRepeatedPunctuation(msg string) string {
	for _, seq := range []string{"...", "!!", "??", "***"} {
		if strings.Contains(msg, seq) {
			return fmt.Sprintf("log message contains repeated punctuation %q", seq)
		}
	}
	return ""
}
