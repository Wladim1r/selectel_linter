package sensitive

import (
	"fmt"
	"strings"
)

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
