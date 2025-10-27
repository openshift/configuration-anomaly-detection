package findings

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestFindings(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Findings Suite")
}

var _ = Describe("Findings", func() {
	var f *Findings

	BeforeEach(func() {
		f = New()
	})

	Describe("Creating findings", func() {
		It("should start empty", func() {
			Expect(f.IsEmpty()).To(BeTrue())
			Expect(f.Count()).To(Equal(0))
		})

		It("should add info findings", func() {
			f.AddInfo("Test Title", "Test Message")
			Expect(f.IsEmpty()).To(BeFalse())
			Expect(f.Count()).To(Equal(1))
			Expect(f.GetAll()[0].Severity).To(Equal(SeverityInfo))
			Expect(f.GetAll()[0].Title).To(Equal("Test Title"))
			Expect(f.GetAll()[0].Message).To(Equal("Test Message"))
		})

		It("should add warning findings", func() {
			f.AddWarning("Warning Title", "Warning Message", "Fix it")
			Expect(f.Count()).To(Equal(1))
			Expect(f.GetAll()[0].Severity).To(Equal(SeverityWarning))
			Expect(f.GetAll()[0].Recommendation).To(Equal("Fix it"))
		})

		It("should add critical findings", func() {
			f.AddCritical("Critical Title", "Critical Message", "Urgent fix")
			Expect(f.Count()).To(Equal(1))
			Expect(f.GetAll()[0].Severity).To(Equal(SeverityCritical))
			Expect(f.GetAll()[0].Recommendation).To(Equal("Urgent fix"))
		})

		It("should add multiple findings", func() {
			f.AddInfo("Info", "Info msg")
			f.AddWarning("Warning", "Warning msg", "Fix")
			f.AddCritical("Critical", "Critical msg", "Fix now")
			Expect(f.Count()).To(Equal(3))
		})
	})

	Describe("Checking finding types", func() {
		It("should detect critical findings", func() {
			f.AddInfo("Info", "msg")
			Expect(f.HasCritical()).To(BeFalse())

			f.AddCritical("Critical", "msg", "fix")
			Expect(f.HasCritical()).To(BeTrue())
		})

		It("should detect warnings", func() {
			f.AddInfo("Info", "msg")
			Expect(f.HasWarnings()).To(BeFalse())

			f.AddWarning("Warning", "msg", "fix")
			Expect(f.HasWarnings()).To(BeTrue())
		})
	})

	Describe("Formatting for PagerDuty", func() {
		It("should show message when no findings", func() {
			output := f.FormatForPagerDuty()
			Expect(output).To(ContainSubstring("No issues detected"))
		})

		It("should group findings by severity", func() {
			f.AddInfo("Info1", "Info message")
			f.AddWarning("Warn1", "Warning message", "Fix it")
			f.AddCritical("Crit1", "Critical message", "Fix now")

			output := f.FormatForPagerDuty()

			// Should contain severity headers
			Expect(output).To(ContainSubstring("🔴 Critical Issues (1)"))
			Expect(output).To(ContainSubstring("⚠️ Warnings (1)"))
			Expect(output).To(ContainSubstring("ℹ️ Information (1)"))

			// Should contain finding details
			Expect(output).To(ContainSubstring("Crit1"))
			Expect(output).To(ContainSubstring("Warn1"))
			Expect(output).To(ContainSubstring("Info1"))

			// Should contain recommendations
			Expect(output).To(ContainSubstring("Fix it"))
			Expect(output).To(ContainSubstring("Fix now"))
		})

		It("should number findings within severity groups", func() {
			f.AddCritical("First Critical", "msg1", "fix1")
			f.AddCritical("Second Critical", "msg2", "fix2")

			output := f.FormatForPagerDuty()

			Expect(output).To(ContainSubstring("1. First Critical"))
			Expect(output).To(ContainSubstring("2. Second Critical"))
		})

		It("should handle multiline messages", func() {
			f.AddWarning("Test", "Line 1\nLine 2\nLine 3", "Fix")

			output := f.FormatForPagerDuty()

			Expect(output).To(ContainSubstring("Line 1"))
			Expect(output).To(ContainSubstring("Line 2"))
			Expect(output).To(ContainSubstring("Line 3"))
		})
	})
})
