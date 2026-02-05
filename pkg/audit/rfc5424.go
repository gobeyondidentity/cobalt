package audit

import (
	"fmt"
	"strings"
	"time"
)

// Additional RFC 5424 severity levels not defined in events.go.
// events.go defines SeverityWarning (4), SeverityNotice (5), SeverityInfo (6).
// These complete the full RFC 5424 severity range (0-7).
const (
	SeverityEmergency Severity = 0
	SeverityAlert     Severity = 1
	SeverityCritical  Severity = 2
	SeverityError     Severity = 3
	SeverityDebug     Severity = 7
)

// Facility represents RFC 5424 syslog facility codes.
type Facility int

const (
	FacLocal0 Facility = 16
)

// SDParam is a single key-value parameter within a structured data element.
type SDParam struct {
	Name  string
	Value string
}

// SDElement is a structured data element with an ID and parameters.
type SDElement struct {
	ID     string // e.g., "cobalt"
	Params []SDParam
}

// Message represents an RFC 5424 syslog message.
type Message struct {
	Facility  Facility
	Severity  Severity
	Timestamp time.Time
	Hostname  string
	AppName   string
	ProcessID string // Use "" for NILVALUE
	MessageID string // The event type: "auth.success", etc.
	SD        []SDElement
	Text      string // Human-readable message body
}

// timestampFormat is the Go format string for RFC 5424 timestamps with fixed 3-digit milliseconds.
const timestampFormat = "2006-01-02T15:04:05.000Z"

// FormatMessage serializes a Message to RFC 5424 wire format.
// Returns the formatted bytes. Does not append a newline.
func FormatMessage(m Message) []byte {
	var b strings.Builder
	b.Grow(384)

	// PRI and VERSION
	fmt.Fprintf(&b, "<%d>1", int(m.Facility)*8+int(m.Severity))

	// TIMESTAMP
	b.WriteByte(' ')
	if m.Timestamp.IsZero() {
		b.WriteByte('-')
	} else {
		b.WriteString(m.Timestamp.UTC().Format(timestampFormat))
	}

	// HOSTNAME, APP-NAME, PROCID, MSGID
	writeField(&b, m.Hostname, 255)
	writeField(&b, m.AppName, 48)
	writeField(&b, m.ProcessID, 128)
	writeField(&b, m.MessageID, 32)

	// STRUCTURED-DATA
	b.WriteByte(' ')
	if len(m.SD) == 0 {
		b.WriteByte('-')
	} else {
		for _, elem := range m.SD {
			b.WriteByte('[')
			b.WriteString(elem.ID)
			for _, p := range elem.Params {
				b.WriteByte(' ')
				b.WriteString(p.Name)
				b.WriteString(`="`)
				escapeSDParamValue(&b, p.Value)
				b.WriteByte('"')
			}
			b.WriteByte(']')
		}
	}

	// MSG
	if m.Text != "" {
		b.WriteByte(' ')
		b.WriteString(m.Text)
	}

	return []byte(b.String())
}

// writeField writes a space followed by the field value, or "-" if empty.
// Truncates to maxLen if exceeded.
func writeField(b *strings.Builder, val string, maxLen int) {
	b.WriteByte(' ')
	if val == "" {
		b.WriteByte('-')
		return
	}
	if len(val) > maxLen {
		val = val[:maxLen]
	}
	b.WriteString(val)
}

// escapeSDParamValue writes val to b, escaping ", \, and ] per RFC 5424 Section 6.3.3.
func escapeSDParamValue(b *strings.Builder, val string) {
	for i := 0; i < len(val); i++ {
		switch val[i] {
		case '"', '\\', ']':
			b.WriteByte('\\')
		}
		b.WriteByte(val[i])
	}
}

// isPrintUSASCII checks that all bytes are in the range 33-126 (visible ASCII).
func isPrintUSASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}
