package rules_test

import (
	"testing"

	"github.com/Wladim1r/loglinter/internal/rules"
)

// ---------------------------------------------------------------------------
// CheckLowercase
// ---------------------------------------------------------------------------

func TestCheckLowercase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		msg     string
		wantErr bool
	}{
		{"valid lowercase", "starting server on port 8080", false},
		{"valid already lower", "failed to connect", false},
		{"empty string", "", false},
		{"upper first letter", "Starting server on port 8080", true},
		{"all caps", "FAILED TO CONNECT", true},
		{"unicode upper", "Запуск", true},
		{"unicode lower is ok", "über", false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := rules.CheckLowercase(tc.msg)
			if (got != "") != tc.wantErr {
				t.Errorf("CheckLowercase(%q) = %q, wantErr=%v", tc.msg, got, tc.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CheckEnglish
// ---------------------------------------------------------------------------

func TestCheckEnglish(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		msg     string
		wantErr bool
	}{
		{"pure ascii", "starting server on port 8080", false},
		{"numbers and symbols", "retry attempt 3/5", false},
		{"cyrillic", "запуск сервера", true},
		{"mixed cyrillic", "starting сервер", true},
		{"chinese", "服务器启动", true},
		{"arabic", "فشل الاتصال", true},
		{"emoji in msg", "server started 🚀", true},
		{"empty", "", false},
		{"allowed en-dash", "step 1\u20132", false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := rules.CheckEnglish(tc.msg)
			if (got != "") != tc.wantErr {
				t.Errorf("CheckEnglish(%q) = %q, wantErr=%v", tc.msg, got, tc.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CheckSpecialChars
// ---------------------------------------------------------------------------

func TestCheckSpecialChars(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		msg          string
		allowedExtra string
		wantErr      bool
	}{
		{"clean message", "server started", "", false},
		{"exclamation", "server started!", "", true},
		{"multiple exclamation", "connection failed!!!", "", true},
		{"ellipsis", "warning: something went wrong...", "", true},
		{"rocket emoji", "server started 🚀", "", true},
		{"check mark emoji", "ok \u2705", "", true},
		{"allowed extra char", "greeting!", "!", false},
		{"path with slash", "reading file /etc/hosts", "", false},
		{"colon allowed", "status: ok", "", false},
		{"hyphen allowed", "user-agent header", "", false},
		{"empty", "", "", false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := rules.CheckSpecialChars(tc.msg, tc.allowedExtra)
			if (got != "") != tc.wantErr {
				t.Errorf("CheckSpecialChars(%q, %q) = %q, wantErr=%v",
					tc.msg, tc.allowedExtra, got, tc.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CheckSensitive
// ---------------------------------------------------------------------------

func TestCheckSensitive(t *testing.T) {
	t.Parallel()

	defaultKW := []string{
		"password", "passwd", "secret", "token", "api_key", "apikey",
		"auth", "credential", "private_key", "access_key",
		"session", "jwt", "bearer", "ssn", "credit_card",
	}

	tests := []struct {
		name     string
		msg      string
		fullExpr string
		wantErr  bool
	}{
		// Clean cases
		{
			"clean auth success",
			"user authenticated successfully",
			`"user authenticated successfully"`,
			false,
		},
		{"api request completed", "api request completed", `"api request completed"`, false},
		{"token validated", "token validated", `"token validated"`, false},

		// Violations in message text
		{"password in msg", "user password: secret123", `"user password: " + password`, true},
		{"token in msg", "token: abc123", `"token: " + token`, true},
		{"api_key in msg", "api_key=xyz", `"api_key=" + apiKey`, true},

		// Violations via variable name in expression
		{"apiKey variable", "api request completed", `"api request completed" + apiKey`, true},
		{"jwtToken variable", "authenticated", `"authenticated " + jwtToken`, true},
		{"userPassword variable", "logging in", `"logging in " + userPassword`, true},

		// Custom keywords
		{"custom keyword match", "private_key exposed", `"private_key exposed"`, true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := rules.CheckSensitive(tc.msg, tc.fullExpr, defaultKW)
			if (got != "") != tc.wantErr {
				t.Errorf("CheckSensitive(%q, %q) = %q, wantErr=%v",
					tc.msg, tc.fullExpr, got, tc.wantErr)
			}
		})
	}
}
