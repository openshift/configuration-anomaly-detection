package micro_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestMicro(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Micro Suite")
}
