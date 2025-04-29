package upgradeconfigsyncfailureover4hr

import (
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGetClusterPullSecret(t *testing.T) {
	tests := []struct {
		name         string
		data         string
		secretToken  string
		expectError  bool
		expectedNote string
	}{
		{
			name:        "happy path",
			data:        "{\"auths\":{\"950916221866.dkr.ecr.us-east-1.amazonaws.com\":{\"auth\":\"testTokenValue\",\"email\":\"\"},\"cloud.openshift.com\":{\"auth\":\"TestAuthValue\",\"email\":\"test_fake_email@redhat.com\"},\"pull.q1w2.quay.rhcloud.com\":{\"auth\":\"TestQuayAuthValue\"},\"quay.io\":{\"auth\":\"TestPersonalAuthValue\",\"email\":\"fake-email@redhat.com\"},\"registry.ci.openshift.org\":{\"auth\":\"TestRegistry-connect-redhat-com-value\"},\"registry.connect.redhat.com\":{\"auth\":\"dWhjLXBvb2wtdGVzdC1wb29sLXZhbHVlLWhlcmU6Q29ycmVjdFZhbHVlCg==\"},\"registry.redhat.io\":{\"auth\":\"TestPersonalTokenTwo\",\"email\":\"test_fake_email@redhat.com\"}}}",
			secretToken: "CorrectValue\n",
			expectError: false,
		},
		{
			name:        "Value mismatch",
			data:        "{\"auths\":{\"950916221866.dkr.ecr.us-east-1.amazonaws.com\":{\"auth\":\"testTokenValue\",\"email\":\"\"},\"cloud.openshift.com\":{\"auth\":\"TestAuthValue\",\"email\":\"test_fake_email@redhat.com\"},\"pull.q1w2.quay.rhcloud.com\":{\"auth\":\"TestQuayAuthValue\"},\"quay.io\":{\"auth\":\"TestPersonalAuthValue\",\"email\":\"fake-email@redhat.com\"},\"registry.ci.openshift.org\":{\"auth\":\"TestRegistry-connect-redhat-com-value\"},\"registry.connect.redhat.com\":{\"auth\":\"dWhjLXBvb2wtdGVzdC1wb29sLXZhbHVlLWhlcmU6Q29ycmVjdFZhbHVlCg==\"},\"registry.redhat.io\":{\"auth\":\"TestPersonalTokenTwo\",\"email\":\"test_fake_email@redhat.com\"}}}",
			secretToken: "IncorrectValue\n",
			expectError: true,
		},
		{
			name:         "No entry for cloud.openshift.com",
			data:         "{\"auths\":{\"950916221866.dkr.ecr.us-east-1.amazonaws.com\":{\"auth\":\"testTokenValue\",\"email\":\"\"},\"MissingValue\":{\"auth\":\"TestAuthValue\",\"email\":\"test_fake_email@redhat.com\"},\"pull.q1w2.quay.rhcloud.com\":{\"auth\":\"TestQuayAuthValue\"},\"quay.io\":{\"auth\":\"TestPersonalAuthValue\",\"email\":\"fake-email@redhat.com\"},\"registry.ci.openshift.org\":{\"auth\":\"TestRegistry-connect-redhat-com-value\"},\"registry.connect.redhat.com\":{\"auth\":\"dWhjLXBvb2wtdGVzdC1wb29sLXZhbHVlLWhlcmU6Q29ycmVjdFZhbHVlCg==\"},\"registry.redhat.io\":{\"auth\":\"TestPersonalTokenTwo\",\"email\":\"test_fake_email@redhat.com\"}}}",
			secretToken:  "IncorrectValue\n",
			expectError:  true,
			expectedNote: "cloud.openshift.com value not found in clusterPullSecret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secretTest := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "pull-secret",
					Namespace: "openshift-config",
				},
				Type: corev1.DockerConfigJsonKey,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(tt.data),
				},
			}
			k8scli := fake.NewClientBuilder().WithObjects(secretTest).Build()
			result, note, _ := getClusterPullSecret(k8scli)
			fmt.Printf("Note is %s", note)
			if result != tt.secretToken {
				if !strings.Contains(note, tt.expectedNote) {
					t.Errorf("Expected note message: %s. Got %s", tt.expectedNote, note)
				}
				if !tt.expectError {
					t.Errorf("expected token %s to match %s", result, tt.secretToken)
				}
			}
		})
	}

}
