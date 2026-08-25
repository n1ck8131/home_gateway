package tunnel

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestConfigSourceIsRedacted(t *testing.T) {
	const secretPath = `C:\secret\provider.conf`
	const secretDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	source := ConfigSource{Path: secretPath, SHA256: secretDigest}

	formatted := fmt.Sprintf("%v %#v", source, source)
	if strings.Contains(formatted, secretPath) || strings.Contains(formatted, secretDigest) {
		t.Fatalf("formatted source leaked its path: %q", formatted)
	}
	data, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secretPath) || strings.Contains(string(data), secretDigest) {
		t.Fatalf("JSON source leaked its path: %s", data)
	}
}

func TestConfigSourceUsesFixedRedactionForFormatVerbs(t *testing.T) {
	const secretPath = `C:\secret\provider.conf`
	source := ConfigSource{Path: secretPath}
	formats := []string{
		"%v", "%+v", "%#v", "%s", "%q",
		"%d", "%o", "%O", "%b", "%x", "%X", "%c", "%U",
		"%e", "%E", "%f", "%F", "%g", "%G", "%t",
		"%20v", "%-20s", "%.3q", "%#+020.8x", "%+12.4d",
	}
	for _, value := range []any{source, &source} {
		for _, format := range formats {
			if got := fmt.Sprintf(format, value); got != "local-config-source(redacted)" {
				t.Errorf("format %q = %q, want fixed redaction", format, got)
			}
		}
	}
}

func TestUnsupportedErrorIsTyped(t *testing.T) {
	err := NewUnsupportedError(OperationStop)
	if !IsUnsupported(err, OperationStop) {
		t.Fatalf("expected typed stop error, got %v", err)
	}
	if IsUnsupported(err, OperationStart) {
		t.Fatal("stop error unexpectedly matched start")
	}
}
