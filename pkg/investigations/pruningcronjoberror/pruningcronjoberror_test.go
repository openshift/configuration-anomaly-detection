package pruningcronjoberror

import (
	"strings"
	"testing"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestInvestigation_checkSeccompError524(t *testing.T) {
	tests := []struct {
		name     string
		objects  []client.Object
		expected bool
		wantErr  bool
	}{
		{
			name: "detects seccomp error in pod condition",
			objects: []client.Object{
				newPodWithCondition("pod-with-seccomp-condition", "Error: container create failed: unable to init seccomp: error loading seccomp filter: errno 524"),
			},
			expected: true,
			wantErr:  false,
		},
		{
			name: "detects seccomp error in container waiting state",
			objects: []client.Object{
				newPodWithWaitingContainer("pod-with-seccomp-waiting", "Error: container create failed: seccomp filter: errno 524"),
			},
			expected: true,
			wantErr:  false,
		},
		{
			name: "detects seccomp error in container terminated state",
			objects: []client.Object{
				newPodWithTerminatedContainer("pod-with-seccomp-terminated", "Error: container create failed: seccomp filter: errno 524"),
			},
			expected: true,
			wantErr:  false,
		},
		{
			name: "no seccomp error found",
			objects: []client.Object{
				newPodWithCondition("pod-without-seccomp", "Normal pod condition"),
				newPodWithWaitingContainer("pod-without-seccomp-waiting", "ImagePullBackOff"),
			},
			expected: false,
			wantErr:  false,
		},
		{
			name:     "no pods in namespace",
			objects:  []client.Object{},
			expected: false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i, err := newTestInvestigation(tt.objects...)
			if err != nil {
				t.Fatalf("failed to create test investigation: %v", err)
			}

			got, err := i.checkSeccompError524(i.kclient)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkSeccompError524() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("checkSeccompError524() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestInvestigation_checkImagePullBackOffPods(t *testing.T) {
	tests := []struct {
		name     string
		objects  []client.Object
		expected bool
		wantErr  bool
	}{
		{
			name: "detects ImagePullBackOff pod",
			objects: []client.Object{
				newPodWithImagePullBackOff("pod-with-imagepullbackoff"),
			},
			expected: true,
			wantErr:  false,
		},
		{
			name: "no ImagePullBackOff pods",
			objects: []client.Object{
				newRunningPod("running-pod"),
				newPodWithWaitingContainer("pod-waiting", "ContainerCreating"),
			},
			expected: false,
			wantErr:  false,
		},
		{
			name:     "no pods in namespace",
			objects:  []client.Object{},
			expected: false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i, err := newTestInvestigation(tt.objects...)
			if err != nil {
				t.Fatalf("failed to create test investigation: %v", err)
			}

			got, err := i.checkImagePullBackOffPods(i.kclient)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkImagePullBackOffPods() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("checkImagePullBackOffPods() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestInvestigation_checkResourceQuotaIssues(t *testing.T) {
	tests := []struct {
		name     string
		objects  []client.Object
		expected bool
		wantErr  bool
	}{
		{
			name: "detects quota issue in job condition",
			objects: []client.Object{
				newFailedJobWithQuotaError("job-with-quota-error"),
			},
			expected: true,
			wantErr:  false,
		},
		{
			name: "detects quota issue in event",
			objects: []client.Object{
				newEventWithQuotaError("quota-event"),
			},
			expected: true,
			wantErr:  false,
		},
		{
			name: "no quota issues",
			objects: []client.Object{
				newSuccessfulJob("successful-job"),
				newEvent("normal-event", "Successfully created pod"),
			},
			expected: false,
			wantErr:  false,
		},
		{
			name:     "no objects in namespace",
			objects:  []client.Object{},
			expected: false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i, err := newTestInvestigation(tt.objects...)
			if err != nil {
				t.Fatalf("failed to create test investigation: %v", err)
			}

			got, err := i.checkResourceQuotaIssues(i.kclient)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkResourceQuotaIssues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("checkResourceQuotaIssues() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestInvestigation_checkOVNIssues(t *testing.T) {
	tests := []struct {
		name     string
		objects  []client.Object
		expected bool
		wantErr  bool
	}{
		{
			name: "detects OVN issue in pod condition",
			objects: []client.Object{
				newPodWithCondition("pod-with-ovn-condition", "context deadline exceeded while waiting for annotations"),
			},
			expected: true,
			wantErr:  false,
		},
		{
			name: "detects OVN issue in event",
			objects: []client.Object{
				newEvent("ovn-event", "failed to create pod network sandbox: ovn-kubernetes error"),
			},
			expected: true,
			wantErr:  false,
		},
		{
			name: "no OVN issues",
			objects: []client.Object{
				newRunningPod("normal-pod"),
				newEvent("normal-event", "Successfully created pod"),
			},
			expected: false,
			wantErr:  false,
		},
		{
			name:     "no objects in namespace",
			objects:  []client.Object{},
			expected: false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i, err := newTestInvestigation(tt.objects...)
			if err != nil {
				t.Fatalf("failed to create test investigation: %v", err)
			}

			got, err := i.checkOVNIssues(i.kclient)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkOVNIssues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("checkOVNIssues() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestInvestigation_getErrorsAndRestartCommand(t *testing.T) {
	tests := []struct {
		name             string
		objects          []client.Object
		expectedErrors   string
		expectedCommand  string
	}{
		{
			name: "failed job and pod",
			objects: []client.Object{
				newFailedJob("failed-job", "Job failed due to timeout"),
				newFailedPod("failed-pod"),
			},
			expectedErrors:  "Job failed-job failed: Job failed due to timeout; Pod failed-pod failed:",
			expectedCommand: "ocm backplane managedjob create SREP/retry-failed-pruning-cronjob # This will retry failed jobs: failed-job",
		},
		{
			name: "no failures",
			objects: []client.Object{
				newSuccessfulJob("successful-job"),
				newRunningPod("running-pod"),
			},
			expectedErrors:  "No specific errors found",
			expectedCommand: "ocm backplane managedjob create SREP/retry-failed-pruning-cronjob",
		},
		{
			name:             "no objects",
			objects:          []client.Object{},
			expectedErrors:   "No specific errors found",
			expectedCommand:  "ocm backplane managedjob create SREP/retry-failed-pruning-cronjob",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i, err := newTestInvestigation(tt.objects...)
			if err != nil {
				t.Fatalf("failed to create test investigation: %v", err)
			}

			errors, command := i.getErrorsAndRestartCommand(i.kclient)
			if !strings.Contains(errors, tt.expectedErrors) {
				t.Errorf("getErrorsAndRestartCommand() errors = %v, want to contain %v", errors, tt.expectedErrors)
			}
			if !strings.Contains(command, "ocm backplane managedjob create SREP/retry-failed-pruning-cronjob") {
				t.Errorf("getErrorsAndRestartCommand() command = %v, want to contain 'ocm backplane managedjob create SREP/retry-failed-pruning-cronjob'", command)
			}
		})
	}
}

func TestInvestigation_executeRemediationSteps(t *testing.T) {
	type result struct {
		recommendations []string
		notes           []string
	}

	tests := []struct {
		name    string
		objects []client.Object
		want    result
	}{
		{
			name: "seccomp error detected",
			objects: []client.Object{
				newPodWithWaitingContainer("seccomp-pod", "seccomp filter: errno 524"),
			},
			want: result{
				recommendations: []string{"Send Servicelog for Seccomp Error 524", "Drain and reboot or replace the affected node"},
				notes:           []string{"Seccomp Error 524 detected"},
			},
		},
		{
			name: "imagepullbackoff detected",
			objects: []client.Object{
				newPodWithImagePullBackOff("imagepull-pod"),
			},
			want: result{
				recommendations: []string{"Check whether the pull secret is valid", "Check cluster-image-operator logs for errors"},
				notes:           []string{"ImagePullBackOff state detected"},
			},
		},
		{
			name: "resource quota detected",
			objects: []client.Object{
				newFailedJobWithQuotaError("quota-job"),
			},
			want: result{
				recommendations: []string{"Send Servicelog for ResourceQuota issue"},
				notes:           []string{"ResourceQuota issue detected"},
			},
		},
		{
			name: "ovn issue detected",
			objects: []client.Object{
				newPodWithCondition("ovn-pod", "context deadline exceeded while waiting for annotations"),
			},
			want: result{
				recommendations: []string{"Restart OVN masters: oc delete po -n openshift-ovn-kubernetes -l app=ovnkube-master"},
				notes:           []string{"OVN issue detected"},
			},
		},
		{
			name: "fallback case - no specific issues",
			objects: []client.Object{
				newFailedJob("generic-failed-job", "Generic failure"),
			},
			want: result{
				recommendations: []string{"Review the errors and execute the restart command if appropriate"},
				notes:           []string{"No specific issue detected"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i, err := newTestInvestigation(tt.objects...)
			if err != nil {
				t.Fatalf("failed to create test investigation: %v", err)
			}

			// Mock investigation.Resources (minimal setup for testing)
			mockResources := &investigation.Resources{}

			err = i.executeRemediationSteps(i.kclient, mockResources)
			if err != nil {
				t.Errorf("executeRemediationSteps() error = %v", err)
				return
			}

			// Verify recommendations
			if len(i.recommendations) != len(tt.want.recommendations) {
				t.Errorf("executeRemediationSteps() recommendations count = %d, want %d", len(i.recommendations), len(tt.want.recommendations))
			}

			for _, expectedRec := range tt.want.recommendations {
				found := false
				for _, rec := range i.recommendations {
					if rec == expectedRec {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("executeRemediationSteps() missing recommendation: %s", expectedRec)
				}
			}

			// Verify notes contain expected messages
			notes := i.notes.String()
			for _, expectedNote := range tt.want.notes {
				if !strings.Contains(notes, expectedNote) {
					t.Errorf("executeRemediationSteps() notes = %v, want to contain %v", notes, expectedNote)
				}
			}
		})
	}
}

// Helper functions to create test objects

func newPodWithCondition(name, message string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-sre-pruning",
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{
					Type:    corev1.PodReady,
					Status:  corev1.ConditionFalse,
					Message: message,
				},
			},
		},
	}
}

func newPodWithWaitingContainer(name, message string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-sre-pruning",
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name: "container",
					State: corev1.ContainerState{
						Waiting: &corev1.ContainerStateWaiting{
							Reason:  "Error",
							Message: message,
						},
					},
				},
			},
		},
	}
}

func newPodWithTerminatedContainer(name, message string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-sre-pruning",
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodFailed,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name: "container",
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							Reason:  "Error",
							Message: message,
						},
					},
				},
			},
		},
	}
}

func newPodWithImagePullBackOff(name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-sre-pruning",
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name: "container",
					State: corev1.ContainerState{
						Waiting: &corev1.ContainerStateWaiting{
							Reason: "ImagePullBackOff",
						},
					},
				},
			},
		},
	}
}

func newRunningPod(name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-sre-pruning",
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name: "container",
					State: corev1.ContainerState{
						Running: &corev1.ContainerStateRunning{
							StartedAt: metav1.Time{Time: time.Now()},
						},
					},
				},
			},
		},
	}
}

func newFailedPod(name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-sre-pruning",
		},
		Status: corev1.PodStatus{
			Phase:   corev1.PodFailed,
			Message: "Pod failed",
		},
	}
}

func newFailedJobWithQuotaError(name string) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-sre-pruning",
		},
		Status: batchv1.JobStatus{
			Conditions: []batchv1.JobCondition{
				{
					Type:    batchv1.JobFailed,
					Status:  corev1.ConditionTrue,
					Message: "pods are forbidden: failed quota: must specify limits.cpu,limits.memory",
				},
			},
		},
	}
}

func newFailedJob(name, message string) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-sre-pruning",
		},
		Status: batchv1.JobStatus{
			Conditions: []batchv1.JobCondition{
				{
					Type:    batchv1.JobFailed,
					Status:  corev1.ConditionTrue,
					Message: message,
				},
			},
		},
	}
}

func newSuccessfulJob(name string) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-sre-pruning",
		},
		Status: batchv1.JobStatus{
			Conditions: []batchv1.JobCondition{
				{
					Type:   batchv1.JobComplete,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}
}

func newEventWithQuotaError(name string) *corev1.Event {
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-sre-pruning",
		},
		Message: "Error creating: pods are forbidden: failed quota: ResourceQuota exceeded",
	}
}

func newEvent(name, message string) *corev1.Event {
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-sre-pruning",
		},
		Message: message,
	}
}

func newFakeClient(objs ...client.Object) (client.Client, error) {
	s := scheme.Scheme
	err := batchv1.AddToScheme(s)
	if err != nil {
		return nil, err
	}

	client := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
	return client, nil
}

type clientImpl struct {
	client.Client
}

func (client clientImpl) Clean() error {
	return nil
}

func newTestInvestigation(testObjects ...client.Object) (Investigation, error) {
	fakeClient, err := newFakeClient(testObjects...)
	if err != nil {
		return Investigation{}, err
	}

	i := Investigation{
		kclient:         clientImpl{fakeClient},
		notes:           notewriter.New("testing", logging.RawLogger),
		recommendations: investigationRecommendations{},
	}
	return i, nil
}

