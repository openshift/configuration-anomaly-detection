package upgradeconfigsyncfailureover4hr

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestUpgradeConfigSyncFailureOver4Hr(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "UpgradeConfigSyncFailureOver4Hr Suite")
}
