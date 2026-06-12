package networkverifier_test

import (
	"encoding/json"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/networkverifier"
	ocmmock "github.com/openshift/configuration-anomaly-detection/pkg/ocm/mock"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func makeSyncSetsWithBundle(bundle string) []hivev1.SyncSet {
	cm := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "user-ca-bundle", Namespace: "openshift-config"},
		Data:       map[string]string{"ca-bundle.crt": bundle},
	}
	cmJSON, err := json.Marshal(cm)
	Expect(err).ToNot(HaveOccurred())

	return []hivev1.SyncSet{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "groups"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "proxy"},
			Spec: hivev1.SyncSetSpec{
				SyncSetCommonSpec: hivev1.SyncSetCommonSpec{
					Resources: []runtime.RawExtension{{Raw: cmJSON}},
				},
			},
		},
	}
}

var _ = Describe("TrustBundle", func() {
	Describe("GetAdditionalTrustBundle", func() {
		const caBundle = "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----"

		var (
			mockCtrl *gomock.Controller
			ocmCli   *ocmmock.MockClient
		)

		BeforeEach(func() {
			mockCtrl = gomock.NewController(GinkgoT())
			ocmCli = ocmmock.NewMockClient(mockCtrl)
		})
		AfterEach(func() {
			mockCtrl.Finish()
		})

		When("cluster is nil", func() {
			It("should return empty string", func() {
				result, err := networkverifier.GetAdditionalTrustBundle(ocmCli, nil)
				Expect(err).ToNot(HaveOccurred())
				Expect(result).To(BeEmpty())
			})
		})

		When("cluster has no additional trust bundle", func() {
			It("should return empty string", func() {
				cluster, err := cmv1.NewCluster().ID("test-id").Build()
				Expect(err).ToNot(HaveOccurred())

				result, err := networkverifier.GetAdditionalTrustBundle(ocmCli, cluster)
				Expect(err).ToNot(HaveOccurred())
				Expect(result).To(BeEmpty())
			})
		})

		When("GetSyncSets fails", func() {
			It("should return the error", func() {
				cluster, err := cmv1.NewCluster().ID("test-id").AdditionalTrustBundle("REDACTED").Build()
				Expect(err).ToNot(HaveOccurred())

				ocmCli.EXPECT().GetSyncSets("test-id").Return(nil, fmt.Errorf("api error"))

				result, err := networkverifier.GetAdditionalTrustBundle(ocmCli, cluster)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to get SyncSets"))
				Expect(result).To(BeEmpty())
			})
		})

		When("no proxy SyncSet exists", func() {
			It("should return an error", func() {
				cluster, err := cmv1.NewCluster().ID("test-id").AdditionalTrustBundle("REDACTED").Build()
				Expect(err).ToNot(HaveOccurred())

				ocmCli.EXPECT().GetSyncSets("test-id").Return([]hivev1.SyncSet{
					{ObjectMeta: metav1.ObjectMeta{Name: "groups"}},
					{ObjectMeta: metav1.ObjectMeta{Name: "identity-providers"}},
				}, nil)

				result, err := networkverifier.GetAdditionalTrustBundle(ocmCli, cluster)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("proxy SyncSet not found"))
				Expect(result).To(BeEmpty())
			})
		})

		When("proxy SyncSet has no ca-bundle.crt ConfigMap", func() {
			It("should return an error", func() {
				cluster, err := cmv1.NewCluster().ID("test-id").AdditionalTrustBundle("REDACTED").Build()
				Expect(err).ToNot(HaveOccurred())

				otherCM, err := json.Marshal(&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "other"},
					Data:       map[string]string{"foo": "bar"},
				})
				Expect(err).ToNot(HaveOccurred())

				ocmCli.EXPECT().GetSyncSets("test-id").Return([]hivev1.SyncSet{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "proxy"},
						Spec: hivev1.SyncSetSpec{
							SyncSetCommonSpec: hivev1.SyncSetCommonSpec{
								Resources: []runtime.RawExtension{{Raw: otherCM}},
							},
						},
					},
				}, nil)

				result, err := networkverifier.GetAdditionalTrustBundle(ocmCli, cluster)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("ca-bundle.crt ConfigMap not found"))
				Expect(result).To(BeEmpty())
			})
		})

		When("proxy SyncSet contains the trust bundle", func() {
			It("should return the CA bundle", func() {
				cluster, err := cmv1.NewCluster().ID("test-id").AdditionalTrustBundle("REDACTED").Build()
				Expect(err).ToNot(HaveOccurred())

				ocmCli.EXPECT().GetSyncSets("test-id").Return(makeSyncSetsWithBundle(caBundle), nil)

				result, err := networkverifier.GetAdditionalTrustBundle(ocmCli, cluster)
				Expect(err).ToNot(HaveOccurred())
				Expect(result).To(Equal(caBundle))
			})
		})
	})
})
