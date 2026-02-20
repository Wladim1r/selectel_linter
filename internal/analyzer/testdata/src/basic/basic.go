package basic

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
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

// CheckSensitive verifies that a log message (or the combined string formed by
// concatenating string literals and variable references) does not contain
// keywords that indicate potentially sensitive data.
//
// keywords is the list of case-insensitive substrings to look for. Callers
// should pass cfg.SensitiveKeywords which may be extended by the user's config.
//
// fullExpr is the full source representation of the argument expression
// (e.g. `"user password: " + password`). We check both the resolved literal
// text and the raw expression so that we catch variable names like `apiKey`.
func CheckSensitive(msg, fullExpr string, keywords []string) string {
	lower := strings.ToLower(msg)
	lowerExpr := strings.ToLower(fullExpr)

	for _, kw := range keywords {
		kw = strings.ToLower(kw)

		// Check the string value of the message itself.
		if strings.Contains(lower, kw) {
			return fmt.Sprintf(
				"log message may contain sensitive data (keyword %q found in message text)",
				kw,
			)
		}

		// Check the raw source expression to catch variable names.
		// e.g.  log.Info("token: " + jwtToken)  → lowerExpr contains "jwttoken"
		// We strip spaces from the expression to normalise camelCase matches:
		// "apiKey" → "apikey" matches the keyword "apikey".
		normalized := strings.ReplaceAll(lowerExpr, "_", "")
		normalized = strings.ReplaceAll(normalized, " ", "")
		kwNorm := strings.ReplaceAll(kw, "_", "")

		if strings.Contains(normalized, kwNorm) {
			return fmt.Sprintf(
				"log message may contain sensitive data (keyword %q found in argument expression)",
				kw,
			)
		}
	}
	return ""
}

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
