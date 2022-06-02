package ccam_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCcam(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Ccam Suite")
}
