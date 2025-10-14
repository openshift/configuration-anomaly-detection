package k8sclient

import (
	"errors"
	"strings"
)

var (
	ErrAPIServerUnavailable = errors.New("kubernetes API server unavailable")
	ErrCannotAccessInfra    = errors.New("cannot access infrastructure cluster's kube-apiserver")
)

func matchError(err error) error {
	switch {
	case strings.Contains(err.Error(), "The cluster could be down or under heavy load"):
		return ErrAPIServerUnavailable
	case strings.Contains(err.Error(), "cannot create remediations on hive, management or service clusters"):
		return ErrCannotAccessInfra
	default:
		return err
	}
}
