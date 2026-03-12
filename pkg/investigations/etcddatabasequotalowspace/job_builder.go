package etcddatabasequotalowspace

import (
	"fmt"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// octosqlEtcdImage is the container image for the etcd snapshot analyzer
	octosqlEtcdImage = "quay.io/redhat_emp1/octosql-etcd:latest"

	// snapshotPath is the path where the snapshot will be saved in the emptyDir volume
	snapshotPath = "/snapshot/etcd.snapshot"
)

// JobConfig contains the configuration needed to build an HCP etcd analysis job
type JobConfig struct {
	Namespace          string // HCP namespace on management cluster (e.g., "ocm-staging-2o8lh1sqlem21729m1oq8pneu67doc3r-alexasmi-test")
	ClusterID          string // Cluster ID for labels
	EtcdPodName        string // e.g., "etcd-0" - used for pod affinity to schedule near this pod
	EtcdContainerImage string // Container image containing etcdctl (extracted from etcd pod spec)
}

// BuildEtcdAnalysisJob creates a Kubernetes Job specification for HCP etcd snapshot analysis
// The job creates an etcd snapshot in an init container, then analyzes it with octosql-etcd
func BuildEtcdAnalysisJob(cfg JobConfig) (*batchv1.Job, error) {
	if cfg.Namespace == "" {
		return nil, fmt.Errorf("namespace is required")
	}
	if cfg.ClusterID == "" {
		return nil, fmt.Errorf("cluster ID is required")
	}
	if cfg.EtcdPodName == "" {
		return nil, fmt.Errorf("etcd pod name is required")
	}
	if cfg.EtcdContainerImage == "" {
		return nil, fmt.Errorf("etcd container image is required")
	}

	// Generate a unique job name based on timestamp
	timestamp := time.Now().Format("20060102-150405")
	jobName := fmt.Sprintf("etcd-analysis-%s", timestamp)

	// TTL: auto-delete job 1 hour after completion
	ttlSecondsAfterFinished := int32(3600)
	// Timeout: max 10 minutes execution time
	activeDeadlineSeconds := int64(600)
	// Backoff: allow 1 retry on failure
	backoffLimit := int32(1)

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: cfg.Namespace,
			Labels: map[string]string{
				"app":        "etcd-snapshot-analysis",
				"cluster-id": cfg.ClusterID,
				"timestamp":  timestamp,
			},
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &ttlSecondsAfterFinished,
			ActiveDeadlineSeconds:   &activeDeadlineSeconds,
			BackoffLimit:            &backoffLimit,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":        "etcd-snapshot-analysis",
						"cluster-id": cfg.ClusterID,
					},
				},
				Spec: corev1.PodSpec{
					// Pod affinity: schedule near the etcd pod on a non-request-serving node
					Affinity: &corev1.Affinity{
						PodAffinity: &corev1.PodAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
								{
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"statefulset.kubernetes.io/pod-name": cfg.EtcdPodName,
										},
									},
									TopologyKey: "kubernetes.io/hostname",
								},
							},
						},
					},
					RestartPolicy: corev1.RestartPolicyNever,

					// Init container: takes the etcd snapshot using etcdctl
					InitContainers: []corev1.Container{
						{
							Name:  "snapshot",
							Image: cfg.EtcdContainerImage,
							Command: []string{
								"/bin/sh",
								"-c",
								fmt.Sprintf("etcdctl snapshot save %s", snapshotPath),
							},
							Env: []corev1.EnvVar{
								{
									Name:  "ETCDCTL_API",
									Value: "3",
								},
								{
									Name:  "ETCDCTL_CACERT",
									Value: "/etc/etcd/tls/etcd-ca/ca.crt",
								},
								{
									Name:  "ETCDCTL_CERT",
									Value: "/etc/etcd/tls/client/etcd-client.crt",
								},
								{
									Name:  "ETCDCTL_KEY",
									Value: "/etc/etcd/tls/client/etcd-client.key",
								},
								{
									Name:  "ETCDCTL_ENDPOINTS",
									Value: "https://etcd-client:2379",
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "snapshot-volume",
									MountPath: "/snapshot",
								},
								{
									Name:      "client-tls",
									MountPath: "/etc/etcd/tls/client",
									ReadOnly:  true,
								},
								{
									Name:      "etcd-ca",
									MountPath: "/etc/etcd/tls/etcd-ca",
									ReadOnly:  true,
								},
							},
						},
					},

					// Analysis container: analyzes the snapshot using octosql-etcd
					Containers: []corev1.Container{
						{
							Name:  "analyzer",
							Image: octosqlEtcdImage,
							Command: []string{
								"/usr/local/bin/analyze-snapshot.sh",
								"--delete",
								snapshotPath,
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "snapshot-volume",
									MountPath: "/snapshot",
								},
							},
						},
					},

					// Volumes
					Volumes: []corev1.Volume{
						{
							Name: "snapshot-volume",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
						{
							Name: "client-tls",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: "etcd-client-tls",
								},
							},
						},
						{
							Name: "etcd-ca",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "etcd-ca",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	return job, nil
}
