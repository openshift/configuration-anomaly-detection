package chgm_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestChgm(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Chgm Suite")
}
