package micro_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/micro"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
)

var _ = Describe("ClusterAccessError", func() {
	var notes *notewriter.NoteWriter

	BeforeEach(func() {
		logging.InitLogger("fatal", "", "")
		notes = notewriter.New("test", logging.RawLogger)
	})

	When("error is a K8s client error with API server unavailable", func() {
		It("should return Done with Escalate", func() {
			err := investigation.K8SClientError{Err: k8sclient.ErrAPIServerUnavailable}
			result := micro.ClusterAccessError(err, notes)
			Expect(result.Done).To(BeTrue())
			Expect(hasActionType(result.Actions, string(executor.ActionTypeEscalateIncident))).To(BeTrue())
			Expect(notes.String()).To(ContainSubstring("kube-api"))
		})
	})

	When("error is a RestConfig error", func() {
		It("should return Done with Escalate", func() {
			err := investigation.RestConfigError{Err: fmt.Errorf("backplane failure")}
			result := micro.ClusterAccessError(err, notes)
			Expect(result.Done).To(BeTrue())
			Expect(hasActionType(result.Actions, string(executor.ActionTypeEscalateIncident))).To(BeTrue())
			Expect(notes.String()).To(ContainSubstring("credentials"))
		})
	})

	When("error is not a cluster access error", func() {
		It("should return not Done", func() {
			err := fmt.Errorf("some other error")
			result := micro.ClusterAccessError(err, notes)
			Expect(result.Done).To(BeFalse())
		})
	})
})
