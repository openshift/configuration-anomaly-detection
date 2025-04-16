package k8sclient

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsAPIServerUnavailable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"TLS timeout", errors.New("TLS handshake timeout"), true},
		{"Connection refused", errors.New("connection refused"), true},
		{"Dial tcp", errors.New("dial tcp 1.2.3.4:443"), true},
		{"Other error", errors.New("some random error"), false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, isAPIServerUnavailable(c.err))
		})
	}
}
