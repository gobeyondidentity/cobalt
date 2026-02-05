package audit

import (
	"strings"
	"testing"
	"time"
)

func TestFormatMessage_BasicAuthSuccess(t *testing.T) {
	t.Log("Testing basic RFC 5424 format with auth.success event")
	ts, err := time.Parse(time.RFC3339Nano, "2026-02-04T15:30:00.000Z")
	if err != nil {
		t.Fatalf("failed to parse timestamp: %v", err)
	}

	msg := Message{
		Facility:  FacLocal0,
		Severity:  SeverityInfo,
		Timestamp: ts,
		Hostname:  "nexus.local",
		AppName:   "nexus",
		MessageID: "auth.success",
		SD: []SDElement{{
			ID: "cobalt",
			Params: []SDParam{
				{Name: "kid", Value: "km_abc123"},
				{Name: "ip", Value: "192.168.1.100"},
			},
		}},
		Text: "DPoP authentication succeeded",
	}

	got := string(FormatMessage(msg))
	want := `<134>1 2026-02-04T15:30:00.000Z nexus.local nexus - auth.success [cobalt kid="km_abc123" ip="192.168.1.100"] DPoP authentication succeeded`

	if got != want {
		t.Errorf("format mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestFormatMessage_NILVALUEFields(t *testing.T) {
	t.Log("Testing that empty hostname, appname, procid, msgid produce NILVALUE (-)")
	ts, _ := time.Parse(time.RFC3339Nano, "2026-02-04T15:30:00.000Z")

	msg := Message{
		Facility:  FacLocal0,
		Severity:  SeverityInfo,
		Timestamp: ts,
		// All string fields empty -> NILVALUE
		SD: []SDElement{{
			ID:     "cobalt",
			Params: []SDParam{{Name: "k", Value: "v"}},
		}},
		Text: "test",
	}

	got := string(FormatMessage(msg))
	want := `<134>1 2026-02-04T15:30:00.000Z - - - - [cobalt k="v"] test`

	if got != want {
		t.Errorf("NILVALUE mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestFormatMessage_ZeroTimestamp(t *testing.T) {
	t.Log("Testing that zero time.Time produces NILVALUE (-) for timestamp")

	msg := Message{
		Facility:  FacLocal0,
		Severity:  SeverityInfo,
		Hostname:  "h",
		AppName:   "a",
		MessageID: "m",
	}

	got := string(FormatMessage(msg))
	want := `<134>1 - h a - m -`

	if got != want {
		t.Errorf("zero timestamp mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestFormatMessage_SDParamEscaping(t *testing.T) {
	t.Log("Testing SD-PARAM value escaping for quote, backslash, and close-bracket")

	ts, _ := time.Parse(time.RFC3339Nano, "2026-01-01T00:00:00.000Z")

	msg := Message{
		Facility:  FacLocal0,
		Severity:  SeverityWarning,
		Timestamp: ts,
		Hostname:  "h",
		AppName:   "a",
		MessageID: "test.escape",
		SD: []SDElement{{
			ID: "cobalt",
			Params: []SDParam{
				{Name: "val", Value: `say "hello"`},
				{Name: "path", Value: `C:\Users\admin`},
				{Name: "bracket", Value: `data]end`},
				{Name: "all", Value: `"\]`},
			},
		}},
	}

	got := string(FormatMessage(msg))
	want := `<132>1 2026-01-01T00:00:00.000Z h a - test.escape [cobalt val="say \"hello\"" path="C:\\Users\\admin" bracket="data\]end" all="\"\\\]"]`

	if got != want {
		t.Errorf("escaping mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestFormatMessage_MultipleSDElements(t *testing.T) {
	t.Log("Testing that multiple SD elements concatenate without separator")

	ts, _ := time.Parse(time.RFC3339Nano, "2026-01-01T00:00:00.000Z")

	msg := Message{
		Facility:  FacLocal0,
		Severity:  SeverityInfo,
		Timestamp: ts,
		Hostname:  "h",
		AppName:   "a",
		MessageID: "m",
		SD: []SDElement{
			{ID: "cobalt", Params: []SDParam{{Name: "k1", Value: "v1"}}},
			{ID: "meta", Params: []SDParam{{Name: "k2", Value: "v2"}}},
		},
		Text: "msg",
	}

	got := string(FormatMessage(msg))
	want := `<134>1 2026-01-01T00:00:00.000Z h a - m [cobalt k1="v1"][meta k2="v2"] msg`

	if got != want {
		t.Errorf("multi-SD mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestFormatMessage_EmptyStructuredData(t *testing.T) {
	t.Log("Testing that no SD elements produces NILVALUE (-)")

	ts, _ := time.Parse(time.RFC3339Nano, "2026-01-01T00:00:00.000Z")

	msg := Message{
		Facility:  FacLocal0,
		Severity:  SeverityInfo,
		Timestamp: ts,
		Hostname:  "h",
		AppName:   "a",
		MessageID: "m",
		Text:      "hello",
	}

	got := string(FormatMessage(msg))
	want := `<134>1 2026-01-01T00:00:00.000Z h a - m - hello`

	if got != want {
		t.Errorf("empty SD mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestFormatMessage_NoMessage(t *testing.T) {
	t.Log("Testing that empty Text omits trailing space and message")

	ts, _ := time.Parse(time.RFC3339Nano, "2026-01-01T00:00:00.000Z")

	msg := Message{
		Facility:  FacLocal0,
		Severity:  SeverityInfo,
		Timestamp: ts,
		Hostname:  "h",
		AppName:   "a",
		MessageID: "m",
		SD: []SDElement{{
			ID:     "cobalt",
			Params: []SDParam{{Name: "k", Value: "v"}},
		}},
	}

	got := string(FormatMessage(msg))
	want := `<134>1 2026-01-01T00:00:00.000Z h a - m [cobalt k="v"]`

	if got != want {
		t.Errorf("no-message mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestFormatMessage_PriorityCalculation(t *testing.T) {
	t.Log("Testing priority = facility*8 + severity for INFO, WARNING, NOTICE")

	tests := []struct {
		name     string
		severity Severity
		wantPri  string
	}{
		{"Local0+INFO=134", SeverityInfo, "<134>"},
		{"Local0+WARNING=132", SeverityWarning, "<132>"},
		{"Local0+NOTICE=133", SeverityNotice, "<133>"},
		{"Local0+ERROR=131", SeverityError, "<131>"},
		{"Local0+EMERGENCY=128", SeverityEmergency, "<128>"},
		{"Local0+DEBUG=135", SeverityDebug, "<135>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := Message{
				Facility: FacLocal0,
				Severity: tt.severity,
				Hostname: "h",
				AppName:  "a",
			}
			got := string(FormatMessage(msg))
			if !strings.HasPrefix(got, tt.wantPri) {
				t.Errorf("priority: got prefix %q, want %q in %q", got[:5], tt.wantPri, got)
			}
		})
	}
}

func TestFormatMessage_FieldTruncation(t *testing.T) {
	t.Log("Testing that hostname > 255 chars gets truncated")

	long := strings.Repeat("x", 300)

	msg := Message{
		Facility: FacLocal0,
		Severity: SeverityInfo,
		Hostname: long,
		AppName:  "a",
	}

	got := string(FormatMessage(msg))
	// The hostname field should be exactly 255 chars
	// Format: "<134>1 - " + hostname + " a - - -"
	parts := strings.SplitN(got, " ", 5) // pri+ver, ts, hostname, rest...
	hostname := parts[2]
	if len(hostname) != 255 {
		t.Errorf("hostname length: got %d, want 255", len(hostname))
	}
}

func TestFormatMessage_UnicodeInParamValue(t *testing.T) {
	t.Log("Testing that multi-byte UTF-8 passes through correctly in PARAM-VALUE")

	ts, _ := time.Parse(time.RFC3339Nano, "2026-01-01T00:00:00.000Z")

	msg := Message{
		Facility:  FacLocal0,
		Severity:  SeverityInfo,
		Timestamp: ts,
		Hostname:  "h",
		AppName:   "a",
		MessageID: "m",
		SD: []SDElement{{
			ID:     "cobalt",
			Params: []SDParam{{Name: "user", Value: "Jose Garcia"}},
		}},
	}

	got := string(FormatMessage(msg))
	want := `<134>1 2026-01-01T00:00:00.000Z h a - m [cobalt user="Jose Garcia"]`

	if got != want {
		t.Errorf("unicode mismatch\n got: %s\nwant: %s", got, want)
	}

	// Verify the Unicode bytes are preserved exactly
	if !strings.Contains(got, "Jose Garcia") {
		t.Error("unicode string not preserved in output")
	}
}

func TestFormatMessage_AllEventSeverities(t *testing.T) {
	t.Log("Testing that each event type in severity map produces correct priority")

	tests := []struct {
		eventType EventType
		severity  Severity
		wantPri   int
	}{
		{EventAuthSuccess, SeverityInfo, 134},
		{EventAuthFailure, SeverityWarning, 132},
		{EventEnrollComplete, SeverityNotice, 133},
		{EventEnrollFailure, SeverityWarning, 132},
		{EventLifecycleRevoke, SeverityWarning, 132},
		{EventLifecycleSuspend, SeverityWarning, 132},
		{EventLifecycleUnsuspend, SeverityNotice, 133},
		{EventLifecycleDecommission, SeverityWarning, 132},
		{EventAttestationBypass, SeverityWarning, 132},
		{EventBootstrapComplete, SeverityNotice, 133},
	}

	for _, tt := range tests {
		t.Run(string(tt.eventType), func(t *testing.T) {
			sev := SeverityFor(tt.eventType)
			if sev != tt.severity {
				t.Errorf("severity for %q: got %d, want %d", tt.eventType, sev, tt.severity)
			}

			pri := int(FacLocal0)*8 + int(sev)
			if pri != tt.wantPri {
				t.Errorf("priority for %q: got %d, want %d", tt.eventType, pri, tt.wantPri)
			}
		})
	}
}

func TestEscapeSDParamValue(t *testing.T) {
	t.Log("Testing escapeSDParamValue directly for edge cases")

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no special chars", "hello world", "hello world"},
		{"quote", `say "hi"`, `say \"hi\"`},
		{"backslash", `path\to\file`, `path\\to\\file`},
		{"close bracket", `data]end`, `data\]end`},
		{"all three", `"\]`, `\"\\\]`},
		{"empty", "", ""},
		{"consecutive specials", `""`, `\"\"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b strings.Builder
			escapeSDParamValue(&b, tt.input)
			got := b.String()
			if got != tt.want {
				t.Errorf("escape(%q): got %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsPrintUSASCII(t *testing.T) {
	t.Log("Testing isPrintUSASCII validation")

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid hostname", "nexus.local", true},
		{"valid app name", "nexus", true},
		{"with space", "hello world", false},
		{"with tab", "hello\tworld", false},
		{"with null", "hello\x00world", false},
		{"empty string", "", true},
		{"all printable", "!~", true},
		{"boundary low (space=32)", " ", false},
		{"boundary high (del=127)", "\x7f", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPrintUSASCII(tt.input)
			if got != tt.want {
				t.Errorf("isPrintUSASCII(%q): got %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
