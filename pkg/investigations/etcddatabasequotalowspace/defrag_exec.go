package etcddatabasequotalowspace

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
)

const endpointStatusCmd = "unset ETCDCTL_ENDPOINTS; etcdctl endpoint status -w json --cluster"

// memberWait is the SOP gap between defragmenting etcd members.
var memberWait = 60 * time.Second

func listEtcdPods(ctx context.Context, k8sClient k8sclient.Client, namespace string) ([]corev1.Pod, error) {
	podList := &corev1.PodList{}
	err := k8sClient.List(ctx, podList, client.InNamespace(namespace), client.MatchingLabels{"app": "etcd"})
	if err != nil {
		return nil, investigation.WrapInfrastructure(err, "listing etcd pods")
	}
	if len(podList.Items) == 0 {
		err = k8sClient.List(ctx, podList, client.InNamespace(namespace), client.MatchingLabels{"k8s-app": "etcd"})
		if err != nil {
			return nil, investigation.WrapInfrastructure(err, "listing etcd pods")
		}
	}
	var running []corev1.Pod
	for _, pod := range podList.Items {
		if pod.Status.Phase == corev1.PodRunning {
			running = append(running, pod)
		}
	}
	if len(running) == 0 {
		return nil, fmt.Errorf("no running etcd pods in %s", namespace)
	}
	return running, nil
}

func readEndpointStatus(ctx context.Context, k8sClient k8sclient.Client, pod *corev1.Pod) ([]endpointStatus, error) {
	out, err := execEtcdctl(ctx, k8sClient, pod, endpointStatusCmd)
	if err != nil {
		return nil, err
	}
	return parseEndpointStatus(out)
}

func execEtcdctl(ctx context.Context, k8sClient k8sclient.Client, pod *corev1.Pod, script string) (string, error) {
	restConfig, err := k8sclient.GetRestConfig(k8sClient)
	if err != nil {
		return "", investigation.WrapInfrastructure(err, "K8s REST config failure")
	}
	out, err := k8sclient.ExecInPod(ctx, restConfig, pod, "etcdctl", []string{"/bin/sh", "-c", script})
	if err != nil {
		return "", investigation.WrapInfrastructure(fmt.Errorf("etcdctl: %w", err), "etcdctl exec failed")
	}
	return out, nil
}

// runDefrag performs the SOP defrag when fragmentation is worth reclaiming.
// dryRun reports the plan and does not change etcd.
func runDefrag(ctx context.Context, k8sClient k8sclient.Client, namespace string, dryRun bool) (defragDecision, error) {
	pods, err := listEtcdPods(ctx, k8sClient, namespace)
	if err != nil {
		return defragDecision{kind: defragFailed}, err
	}
	before, err := readEndpointStatus(ctx, k8sClient, &pods[0])
	if err != nil {
		return defragDecision{kind: defragFailed}, err
	}
	if !worthDefrag(before) {
		logging.Infof("etcd reclaimable %d bytes, below %d, skipping defrag", reclaimableBytes(before), minReclaimBytes)
		return defragDecision{kind: defragNoReclaim}, nil
	}
	order := defragOrder(before)
	var planned []string
	for _, member := range order {
		pod := podForEndpoint(pods, member.Endpoint)
		name := member.Endpoint
		if pod != nil {
			name = pod.Name
		}
		planned = append(planned, name)
	}
	logging.Infof("etcd defrag plan: %s", strings.Join(planned, ", "))
	if dryRun {
		return defragDecision{kind: defragNoReclaim}, nil
	}
	for i, member := range order {
		pod := podForEndpoint(pods, member.Endpoint)
		if pod == nil {
			return defragDecision{kind: defragFailed}, fmt.Errorf("no etcd pod for endpoint %s", member.Endpoint)
		}
		if _, err := execEtcdctl(ctx, k8sClient, pod, "unset ETCDCTL_ENDPOINTS; etcdctl --command-timeout=30s --endpoints=https://localhost:2379 defrag"); err != nil {
			return defragDecision{kind: defragFailed}, err
		}
		if i < len(order)-1 {
			time.Sleep(memberWait)
		}
	}
	leader := order[len(order)-1]
	if pod := podForEndpoint(pods, leader.Endpoint); pod != nil {
		_, _ = execEtcdctl(ctx, k8sClient, pod, "unset ETCDCTL_ENDPOINTS; etcdctl alarm disarm")
	}
	after, err := readEndpointStatus(ctx, k8sClient, &pods[0])
	if err != nil {
		return defragDecision{kind: defragFailed}, err
	}
	return decideDefrag(before, after, nil), nil
}

func podForEndpoint(pods []corev1.Pod, endpoint string) *corev1.Pod {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil
	}
	host := u.Hostname()
	for i := range pods {
		if pods[i].Status.PodIP == host {
			return &pods[i]
		}
	}
	if len(pods) == 1 {
		return &pods[0]
	}
	return nil
}
