package rules

import (
	"fmt"
	"strings"
)

func tokenizeWords(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch {
		case r >= 'a' && r <= 'z':
			return false
		case r >= '0' && r <= '9':
			return false
		case r == '_':
			return false
		default:
			return true
		}
	})
}

// stripStringLiterals removes the contents of Go-style string literals from an
// expression so we can scan identifiers without being affected by the literal
// text itself. It supports:
// - double-quoted strings with escaping
// - raw backtick strings
func stripStringLiterals(expr string) string {
	var b strings.Builder
	b.Grow(len(expr))

	inDouble := false
	inRaw := false
	escape := false

	for _, r := range expr {
		if inRaw {
			if r == '`' {
				inRaw = false
				b.WriteRune(' ')
			}
			continue
		}
		if inDouble {
			if escape {
				escape = false
				continue
			}
			if r == '\\' {
				escape = true
				continue
			}
			if r == '"' {
				inDouble = false
				b.WriteRune(' ')
			}
			continue
		}

		switch r {
		case '"':
			inDouble = true
			b.WriteRune(' ')
		case '`':
			inRaw = true
			b.WriteRune(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
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
	tokens := tokenizeWords(lower)

	// Some words commonly follow tokens like "token"/"auth" in a non-sensitive
	// status-style message (e.g. "token validated"). This is a pragmatic
	// false-positive reducer: if a sensitive keyword appears as a standalone
	// word and is immediately followed by one of these, we do not flag.
	safeNext := map[string]struct{}{
		"ok":           {},
		"success":      {},
		"successful":   {},
		"succeeded":    {},
		"failed":       {},
		"failure":      {},
		"error":        {},
		"invalid":      {},
		"missing":      {},
		"present":      {},
		"enabled":      {},
		"disabled":     {},
		"created":      {},
		"generated":    {},
		"refreshed":    {},
		"expired":      {},
		"validated":    {},
		"completed":    {},
		"revoked":      {},
		"rotated":      {},
		"updated":      {},
		"authorized":   {},
		"unauthorized": {},
	}

	for _, kw := range keywords {
		kw = strings.ToLower(kw)

		// Check the message text itself, but match by word/tokens rather than raw
		// substring. This avoids noisy matches like keyword "auth" inside
		// "authenticated".
		for i, tok := range tokens {
			if tok != kw {
				continue
			}
			if i+1 < len(tokens) {
				if _, ok := safeNext[tokens[i+1]]; ok {
					break
				}
			}
			return fmt.Sprintf(
				"log message may contain sensitive data (keyword %q found in message text)",
				kw,
			)
		}

		// Check the raw source expression to catch variable names.
		// e.g.  log.Info("token: " + jwtToken)  → lowerExpr contains "jwttoken"
		// We strip spaces from the expression to normalise camelCase matches:
		// "apiKey" → "apikey" matches the keyword "apikey".
		exprNoStrings := stripStringLiterals(lowerExpr)
		normalized := strings.ReplaceAll(exprNoStrings, "_", "")
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
