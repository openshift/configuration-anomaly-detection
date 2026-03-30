package etcddatabasequotalowspace

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestBuildEtcdAnalysisJob(t *testing.T) {
	tests := []struct {
		name    string
		config  JobConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid configuration",
			config: JobConfig{
				Namespace:          "ocm-staging-cluster-namespace",
				ClusterID:          "test-cluster-123",
				EtcdPodName:        "etcd-0",
				EtcdContainerImage: "quay.io/openshift/etcd:v4.15",
			},
			wantErr: false,
		},
		{
			name: "missing namespace",
			config: JobConfig{
				ClusterID:          "test-cluster-123",
				EtcdPodName:        "etcd-0",
				EtcdContainerImage: "quay.io/openshift/etcd:v4.15",
			},
			wantErr: true,
			errMsg:  "namespace is required",
		},
		{
			name: "missing cluster ID",
			config: JobConfig{
				Namespace:          "ocm-staging-cluster-namespace",
				EtcdPodName:        "etcd-0",
				EtcdContainerImage: "quay.io/openshift/etcd:v4.15",
			},
			wantErr: true,
			errMsg:  "cluster ID is required",
		},
		{
			name: "missing etcd pod name",
			config: JobConfig{
				Namespace:          "ocm-staging-cluster-namespace",
				ClusterID:          "test-cluster-123",
				EtcdContainerImage: "quay.io/openshift/etcd:v4.15",
			},
			wantErr: true,
			errMsg:  "etcd pod name is required",
		},
		{
			name: "missing etcd container image",
			config: JobConfig{
				Namespace:   "ocm-staging-cluster-namespace",
				ClusterID:   "test-cluster-123",
				EtcdPodName: "etcd-0",
			},
			wantErr: true,
			errMsg:  "etcd container image is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job, err := BuildEtcdAnalysisJob(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Errorf("BuildEtcdAnalysisJob() expected error but got none")
					return
				}
				if err.Error() != tt.errMsg {
					t.Errorf("BuildEtcdAnalysisJob() error = %v, want %v", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("BuildEtcdAnalysisJob() unexpected error: %v", err)
				return
			}

			if job == nil {
				t.Errorf("BuildEtcdAnalysisJob() returned nil job")
				return
			}

			if job.Namespace != tt.config.Namespace {
				t.Errorf("Job namespace = %v, want %v", job.Namespace, tt.config.Namespace)
			}

			if job.Labels["cluster-id"] != tt.config.ClusterID {
				t.Errorf("Job cluster-id label = %v, want %v", job.Labels["cluster-id"], tt.config.ClusterID)
			}

			if job.Spec.TTLSecondsAfterFinished == nil || *job.Spec.TTLSecondsAfterFinished != 3600 {
				t.Errorf("Job TTLSecondsAfterFinished = %v, want 3600", job.Spec.TTLSecondsAfterFinished)
			}

			if job.Spec.ActiveDeadlineSeconds == nil || *job.Spec.ActiveDeadlineSeconds != 600 {
				t.Errorf("Job ActiveDeadlineSeconds = %v, want 600", job.Spec.ActiveDeadlineSeconds)
			}

			if job.Spec.BackoffLimit == nil || *job.Spec.BackoffLimit != 1 {
				t.Errorf("Job BackoffLimit = %v, want 1", job.Spec.BackoffLimit)
			}
		})
	}
}

func TestJobSpecPodAffinity(t *testing.T) {
	config := JobConfig{
		Namespace:          "ocm-staging-cluster-namespace",
		ClusterID:          "test-cluster-123",
		EtcdPodName:        "etcd-0",
		EtcdContainerImage: "quay.io/openshift/etcd:v4.15",
	}

	job, err := BuildEtcdAnalysisJob(config)
	if err != nil {
		t.Fatalf("BuildEtcdAnalysisJob() unexpected error: %v", err)
	}

	affinity := job.Spec.Template.Spec.Affinity
	if affinity == nil {
		t.Fatal("Job pod affinity is nil, expected it to be configured")
	}

	if affinity.PodAffinity == nil {
		t.Fatal("Job pod affinity PodAffinity is nil")
	}

	if len(affinity.PodAffinity.RequiredDuringSchedulingIgnoredDuringExecution) == 0 {
		t.Fatal("Job pod affinity has no required terms")
	}

	term := affinity.PodAffinity.RequiredDuringSchedulingIgnoredDuringExecution[0]

	if term.LabelSelector.MatchLabels["statefulset.kubernetes.io/pod-name"] != config.EtcdPodName {
		t.Errorf("Pod affinity pod-name = %v, want %v",
			term.LabelSelector.MatchLabels["statefulset.kubernetes.io/pod-name"],
			config.EtcdPodName)
	}

	if term.TopologyKey != "kubernetes.io/hostname" {
		t.Errorf("Pod affinity topology key = %v, want kubernetes.io/hostname", term.TopologyKey)
	}
}

func TestJobSpecInitContainer(t *testing.T) {
	config := JobConfig{
		Namespace:          "ocm-staging-cluster-namespace",
		ClusterID:          "test-cluster-123",
		EtcdPodName:        "etcd-0",
		EtcdContainerImage: "quay.io/openshift/etcd:v4.15",
	}

	job, err := BuildEtcdAnalysisJob(config)
	if err != nil {
		t.Fatalf("BuildEtcdAnalysisJob() unexpected error: %v", err)
	}

	if len(job.Spec.Template.Spec.InitContainers) != 1 {
		t.Fatalf("Expected 1 init container, got %d", len(job.Spec.Template.Spec.InitContainers))
	}

	initContainer := job.Spec.Template.Spec.InitContainers[0]

	if initContainer.Name != "snapshot" {
		t.Errorf("Init container name = %v, want snapshot", initContainer.Name)
	}

	if initContainer.Image != config.EtcdContainerImage {
		t.Errorf("Init container image = %v, want %v", initContainer.Image, config.EtcdContainerImage)
	}

	expectedEnvVars := map[string]string{
		"ETCDCTL_API":       "3",
		"ETCDCTL_CACERT":    "/etc/etcd/tls/etcd-ca/ca.crt",
		"ETCDCTL_CERT":      "/etc/etcd/tls/client/etcd-client.crt",
		"ETCDCTL_KEY":       "/etc/etcd/tls/client/etcd-client.key",
		"ETCDCTL_ENDPOINTS": "https://etcd-client:2379",
	}

	for expectedName, expectedValue := range expectedEnvVars {
		found := false
		for _, env := range initContainer.Env {
			if env.Name == expectedName {
				found = true
				if env.Value != expectedValue {
					t.Errorf("Init container env %s = %v, want %v", expectedName, env.Value, expectedValue)
				}
				break
			}
		}
		if !found {
			t.Errorf("Init container missing env var %s", expectedName)
		}
	}

	expectedVolumeMounts := []struct {
		name      string
		mountPath string
	}{
		{"snapshot-volume", "/snapshot"},
		{"client-tls", "/etc/etcd/tls/client"},
		{"etcd-ca", "/etc/etcd/tls/etcd-ca"},
	}

	for _, expected := range expectedVolumeMounts {
		found := false
		for _, mount := range initContainer.VolumeMounts {
			if mount.Name == expected.name {
				found = true
				if mount.MountPath != expected.mountPath {
					t.Errorf("Init container volume mount %s mountPath = %v, want %v",
						expected.name, mount.MountPath, expected.mountPath)
				}
				break
			}
		}
		if !found {
			t.Errorf("Init container missing volume mount %s", expected.name)
		}
	}
}

func TestJobSpecAnalysisContainer(t *testing.T) {
	config := JobConfig{
		Namespace:          "ocm-staging-cluster-namespace",
		ClusterID:          "test-cluster-123",
		EtcdPodName:        "etcd-0",
		EtcdContainerImage: "quay.io/openshift/etcd:v4.15",
	}

	job, err := BuildEtcdAnalysisJob(config)
	if err != nil {
		t.Fatalf("BuildEtcdAnalysisJob() unexpected error: %v", err)
	}

	if len(job.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("Expected 1 container, got %d", len(job.Spec.Template.Spec.Containers))
	}

	container := job.Spec.Template.Spec.Containers[0]

	if container.Name != "analyzer" {
		t.Errorf("Analysis container name = %v, want analyzer", container.Name)
	}

	if container.Image != octosqlImage {
		t.Errorf("Analysis container image = %v, want %v", container.Image, octosqlImage)
	}

	expectedCommand := []string{
		"/usr/local/bin/analyze-snapshot.sh",
		"--delete",
		snapshotPath,
	}

	if len(container.Command) != len(expectedCommand) {
		t.Errorf("Analysis container command length = %d, want %d", len(container.Command), len(expectedCommand))
	} else {
		for i, cmd := range expectedCommand {
			if container.Command[i] != cmd {
				t.Errorf("Analysis container command[%d] = %v, want %v", i, container.Command[i], cmd)
			}
		}
	}

	found := false
	for _, mount := range container.VolumeMounts {
		if mount.Name == "snapshot-volume" {
			found = true
			if mount.MountPath != "/snapshot" {
				t.Errorf("Analysis container snapshot volume mountPath = %v, want /snapshot", mount.MountPath)
			}
			break
		}
	}
	if !found {
		t.Error("Analysis container missing snapshot-volume mount")
	}
}

func TestJobSpecVolumes(t *testing.T) {
	config := JobConfig{
		Namespace:          "ocm-staging-cluster-namespace",
		ClusterID:          "test-cluster-123",
		EtcdPodName:        "etcd-0",
		EtcdContainerImage: "quay.io/openshift/etcd:v4.15",
	}

	job, err := BuildEtcdAnalysisJob(config)
	if err != nil {
		t.Fatalf("BuildEtcdAnalysisJob() unexpected error: %v", err)
	}

	volumes := job.Spec.Template.Spec.Volumes

	if len(volumes) != 3 {
		t.Fatalf("Expected 3 volumes, got %d", len(volumes))
	}

	var snapshotVolume *corev1.Volume
	for i := range volumes {
		if volumes[i].Name == "snapshot-volume" {
			snapshotVolume = &volumes[i]
			break
		}
	}

	if snapshotVolume == nil {
		t.Fatal("snapshot-volume not found")
	}

	if snapshotVolume.EmptyDir == nil {
		t.Error("snapshot-volume should be an emptyDir volume")
	}

	var clientTLSVolume *corev1.Volume
	for i := range volumes {
		if volumes[i].Name == "client-tls" {
			clientTLSVolume = &volumes[i]
			break
		}
	}

	if clientTLSVolume == nil {
		t.Fatal("client-tls volume not found")
	}

	if clientTLSVolume.Secret == nil {
		t.Error("client-tls should be a secret volume")
	} else if clientTLSVolume.Secret.SecretName != "etcd-client-tls" {
		t.Errorf("client-tls secret name = %v, want etcd-client-tls",
			clientTLSVolume.Secret.SecretName)
	}

	var etcdCAVolume *corev1.Volume
	for i := range volumes {
		if volumes[i].Name == "etcd-ca" {
			etcdCAVolume = &volumes[i]
			break
		}
	}

	if etcdCAVolume == nil {
		t.Fatal("etcd-ca volume not found")
	}

	if etcdCAVolume.ConfigMap == nil {
		t.Error("etcd-ca should be a configMap volume")
	} else if etcdCAVolume.ConfigMap.Name != "etcd-ca" {
		t.Errorf("etcd-ca configMap name = %v, want etcd-ca",
			etcdCAVolume.ConfigMap.Name)
	}
}

func TestJobSpecRestartPolicy(t *testing.T) {
	config := JobConfig{
		Namespace:          "ocm-staging-cluster-namespace",
		ClusterID:          "test-cluster-123",
		EtcdPodName:        "etcd-0",
		EtcdContainerImage: "quay.io/openshift/etcd:v4.15",
	}

	job, err := BuildEtcdAnalysisJob(config)
	if err != nil {
		t.Fatalf("BuildEtcdAnalysisJob() unexpected error: %v", err)
	}

	if job.Spec.Template.Spec.RestartPolicy != corev1.RestartPolicyNever {
		t.Errorf("Job restart policy = %v, want Never", job.Spec.Template.Spec.RestartPolicy)
	}
}
