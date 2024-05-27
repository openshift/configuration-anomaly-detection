package notewriter

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
)

type NoteWriter struct {
	investigationName string
	sb                strings.Builder
	logger            *zap.SugaredLogger
}

// New initializes a new NoteWriter with an optional logger.
// The note is initialized with an investigation header in the following format:
// 🤖 Automated %s pre-investigation 🤖
// ===========================
//
// E.g.
// 🤖 Automated CHGM pre-investigation 🤖
// ===========================
func New(investigationName string, logger *zap.SugaredLogger) *NoteWriter {
	nw := &NoteWriter{investigationName, strings.Builder{}, logger}
	nw.sb.WriteString(fmt.Sprintf("🤖 Automated %s pre-investigation 🤖\n", investigationName))
	nw.sb.WriteString("===========================\n")
	return nw
}

// String() returns the current full string format of the built note
func (n *NoteWriter) String() string {
	return n.sb.String()
}

func (n *NoteWriter) writeWithLog(format string, a ...any) {
	if n.logger != nil {
		n.logger.Infof(format, a...)
	}

	n.sb.WriteString(fmt.Sprintf(format, a...))
}

// AppendSuccess should be used when a CAD check succeeded, e.g.
// ✅ Network Verifier Passed
// Format appended to the note:
// ✅ <my string>\n
func (n *NoteWriter) AppendSuccess(format string, a ...any) {
	n.writeWithLog("✅ %s\n", fmt.Sprintf(format, a...))
}

// AppendWarning should be used when a CAD check showed an issue, e.g.
// ⚠️ Network Verifier Failed with the following errors: error1, error2, error3
// Format appended to the note:
// ⚠️ <my string>\n
func (n *NoteWriter) AppendWarning(format string, a ...any) {
	n.writeWithLog("⚠️ %s\n", fmt.Sprintf(format, a...))
}

// AppendAutomation should to indicate CAD took an automated action, e.g.
// 🤖 Sent service log: "This is the service log message"
// Format appended to the note:
// 🤖 <my string>\n
func (n *NoteWriter) AppendAutomation(format string, a ...any) {
	n.writeWithLog("🤖 %s\n", fmt.Sprintf(format, a...))
}
