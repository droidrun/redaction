package redaction_test

import (
	"log/slog"
	"os"

	redaction "github.com/droidrun/redaction/go"
)

// A slog handler that redacts every attribute by its key name and scans every string.
func ExampleRedactField() {
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.TimeKey {
				return slog.Attr{} // keep the example output stable
			}
			return slog.Any(attr.Key, redaction.RedactField(attr.Key, attr.Value.Resolve().Any()))
		},
	})
	logger := slog.New(handler)
	logger.Info("login", "password", "hunter2xx", "max_tokens", 100)
	logger.Info("retry", "pin", 1234, "note", "api_key=Zq9abcDEF123ghi_x")
	// Output:
	// level=INFO msg=login password=[REDACTED:key-context] max_tokens=100
	// level=INFO msg=retry pin=[REDACTED:key-context] note="api_key=[REDACTED:generic-keyword]"
}
