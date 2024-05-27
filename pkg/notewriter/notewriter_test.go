package notewriter

import (
	"testing"
)

var (
	testInvestigationName = "CHGM"

	expectedOutput = `🤖 Automated CHGM pre-investigation 🤖
===========================
✅ Network Verifier Succeeded: 123
⚠️ Network Verifier Failed: 123
🤖 Sent servicelog for network misconfiguration: 123
`
)

func TestNoteWriter(t *testing.T) {
	notesWriter := New(testInvestigationName, nil)
	notesWriter.AppendSuccess("Network Verifier Succeeded: 123")
	notesWriter.AppendWarning("Network Verifier Failed: 123")
	notesWriter.AppendAutomation("Sent servicelog for network misconfiguration: 123")

	res := notesWriter.String()

	if res != expectedOutput {
		t.Fatalf("NoteWriter output does not match expected test output.\n NoteWriter output:\n%s\n\n Expected output:\n%s", res, expectedOutput)
	}
}

func TestNoteWriterFormat(t *testing.T) {
	notesWriter := New(testInvestigationName, nil)
	notesWriter.AppendSuccess("Network Verifier Succeeded: %s", "123")
	notesWriter.AppendWarning("Network Verifier Failed: %s", "123")
	notesWriter.AppendAutomation("Sent servicelog for network misconfiguration: %s", "123")

	res := notesWriter.String()

	if res != expectedOutput {
		t.Fatalf("NoteWriter output does not match expected test output.\n NoteWriter output:\n%s\n\n Expected output:\n%s", res, expectedOutput)
	}
}
