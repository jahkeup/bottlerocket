package host_ctr


import (
	"testing"

	"github.com/containerd/containerd/pkg/testutil"
	_ "github.com/containerd/containerd/pkg/testutil"
)

func TestMainPullImageDockerHub(t *testing.T) {
	testutil.RequiresRoot(t)
	// TODO: write test with daemon to use.
}

func TestMainPullImageECR(t *testing.T) {
	testutil.RequiresRoot(t)
	// TODO: write test with daemon to use.
}
