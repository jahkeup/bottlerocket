package host_ctr_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/containerd/containerd/log/logtest"

	"host_ctr"
)

func TestMainErrors(t *testing.T) {
	testcases := []struct{
		args []string
		expect int
	}{
		{ args: []string{}, expect: host_ctr.StatusUsageError },
		{ args: []string{"-source"}, expect: host_ctr.StatusUsageError },
		{ args: []string{"-source", "source.ref/test-image:unit-test"}, expect: host_ctr.StatusUsageError },
		{ args: []string{"-source", "source.ref/test-image:unit-test"}, expect: host_ctr.StatusUsageError },
		{ args: []string{
			"-source", "source.ref/test-image:unit-test",
			"-ctr-id", "",
		}, expect: host_ctr.StatusUsageError },
		{ args: []string{
			"-source", "source.ref/test-image:unit-test",
			"-pull-image-only",
			"-containerd-socket", "/",
		}, expect: host_ctr.StatusRunError },
		{ args: []string{
			"-source", "source.ref/test-image:unit-test",
			"-ctr-id", "bar",
			"-containerd-socket", "/",
		}, expect: host_ctr.StatusRunError },
	}

	for _, tc := range testcases {
		t.Run(fmt.Sprintf("args/%q", tc.args), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10 * time.Millisecond)
			defer cancel()
			assert.Equal(t, tc.expect, host_ctr.Main(logtest.WithT(ctx, t), tc.args))
		})
	}
}
