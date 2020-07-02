package host_ctr

import (
	"context"
	errs "errors"
	"flag"
	"math/rand"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/awslabs/amazon-ecr-containerd-resolver/ecr"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/contrib/seccomp"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/reference"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
)

// Expecting to match ECR image names of the form:
//
// Example 1: 777777777777.dkr.ecr.us-west-2.amazonaws.com/my_image:latest
// Example 2: 777777777777.dkr.ecr.cn-north-1.amazonaws.com.cn/my_image:latest
var ecrRegex = regexp.MustCompile(`(^[a-zA-Z0-9][a-zA-Z0-9-_]*)\.dkr\.ecr\.([a-zA-Z0-9][a-zA-Z0-9-_]*)\.amazonaws\.com(\.cn)?.*`)

var jitterRand = rand.New(rand.NewSource(time.Now().UnixNano()))

const (
	// StatusRunError is returned when host-ctr is encounters a runtime error.
	StatusRunError = 1
	// StatusUsageError is returned when host-ctr is unable to execute with the
	// provided configuration.
	StatusUsageError = 2
)

// Main executes host-ctr as needed in main function.
func Main(ctx context.Context, args []string) int {
	// Setup flag parser.
	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	hc := &HostContainer{}
	flags.SetOutput(log.L.Logger.Out)

	flags.StringVar(&hc.ContainerID, "ctr-id", "", "The ID of the container to be started")
	flags.StringVar(&hc.Source, "source", "", "The image to be pulled")
	flags.BoolVar(&hc.Superpowered, "superpowered", false, "Specifies whether to launch the container in `superpowered` mode or not")
	flags.BoolVar(&hc.PullImageOnly, "pull-image-only", false, "Only pull and unpack the container image, do not start any container task")
	flags.StringVar(&hc.ContainerdSocket, "containerd-socket", "/run/host-containerd/containerd.sock", "Specifies the path to the containerd socket. Defaults to `/run/host-containerd/containerd.sock`")
	flags.StringVar(&hc.Namespace, "namespace", "default", "Specifies the containerd namespace")

	err := flags.Parse(args)
	if err != nil {
		log.L.WithError(err).Error("failed to parse provided args")
		return StatusUsageError
	}
	log.L.WithField("config", hc).WithField("args", args).Debug("configured host-container run")

	// Validate provided arguments.

	// Image source must always be provided.
	if hc.Source == "" {
		log.L.Error("source image must be provided")
		flags.Usage()
		return StatusUsageError
	}

	// Container ID must be provided unless the goal is to pull an image.
	if hc.ContainerID == "" && !hc.PullImageOnly {
		log.L.Error("container ID must be provided")
		flags.Usage()
		return StatusUsageError
	}

	// Run host-ctr!
	log.L.WithField("config", hc).Debug("executing")
	exitCode, _ := hc.execute(ctx)
	return exitCode
}

// HostContainer manages a supervised run of a bottlerocket host-container.
type HostContainer struct {
	// ContainerID is the ID given to the managed host-container.
	ContainerID string
	// Source is the image source URI used for the managed host-container.
	Source string
	// Superpowered indicates that the managed host-container should be granted
	// additional privileges and have access to sensitive mounts.
	Superpowered bool
	// PullImageOnly indicates that the managed container should not be started
	// after pulling the specified Source image.
	PullImageOnly bool
	// ContainerdSocket is the address of the containerd daemon that will run
	// the managed host-container.
	ContainerdSocket string
	// Namespace is the containerd namespace used when running the mananged
	// host-container.
	Namespace string
}

func (hc *HostContainer) Execute(ctx context.Context) error {
	_, err := hc.execute(ctx)
	return err
}

func (hc *HostContainer) execute(runCtx context.Context) (int, error) {
	// Setup execution contexts with signal handler to gracefully exit when
	// killed.
	ctx, cancel := context.WithCancel(runCtx)
	defer cancel()
	go cancelOnSignal(runCtx, cancel)

	log.G(ctx).
		WithField("socket", hc.ContainerdSocket).
		WithField("namespace", hc.Namespace).
		Debug("connecting to containerd")
	ctx = namespaces.WithNamespace(ctx, hc.Namespace)
	// Setup containerd client using provided socket.
	client, err := containerd.New(hc.ContainerdSocket, containerd.WithDefaultNamespace(hc.Namespace))
	if err != nil {
		log.G(ctx).
			WithError(err).
			WithField("socket", hc.ContainerdSocket).
			WithField("namespace", hc.Namespace).
			Error("Failed to connect to containerd")
		return StatusRunError, err
	}
	defer client.Close()

	// Parse the source ref if it looks like an ECR ref.
	ref := hc.Source
	isECRImage := ecrRegex.MatchString(ref)
	if isECRImage {
		ecrRef, err := ecr.ParseImageURI(ref)
		if err != nil {
			log.G(ctx).WithError(err).WithField("source", hc.Source).Error("Failed to parse ECR reference")
			return StatusRunError, err
		}
		ref = ecrRef.Canonical()
		log.G(ctx).
			WithField("source", hc.Source).
			WithField("ref", ref).
			Debug("Parsed ECR reference from URI")
	}

	img, err := pullImage(ctx, ref, client)
	if err != nil {
		log.G(ctx).WithField("ref", ref).Error(err)
		return StatusRunError, err
	}

	// When the image is from ECR, the image reference will be converted its ref
	// format. This is of the form of `"ecr.aws/" + ECR repository ARN +
	// label/digest`. See the resolver for details on this format -
	// https://github.com/awslabs/amazon-ecr-containerd-resolver.
	//
	// If the image was pulled from ECR, add `source` ref pointing to the same
	// image so other clients can locate it using both `source` and the parsed
	// ECR ref.
	if isECRImage {
		// Add additional `source` tag on ECR image for other clients.
		log.G(ctx).
			WithField("ref", ref).
			WithField("source", hc.Source).
			Debug("Adding source tag on pulled image")
		if err := tagImage(ctx, ref, hc.Source, client); err != nil {
			log.G(ctx).
				WithError(err).
				WithField("source", hc.Source).
				WithField("ref", ref).
				Error("Failed to add source tag on pulled image")
			return StatusRunError, err
		}
	}

	// If we're only pulling and unpacking the image, we're done here.
	if hc.PullImageOnly {
		log.G(ctx).Info("Not starting host container, pull-image-only mode specified")
		return 0, nil
	}

	// Clean up target container if it already exists before starting container
	// task.
	if err := deleteCtrIfExists(ctx, client, hc.ContainerID); err != nil {
		return StatusRunError, nil
	}

	// Get the cgroup path of the systemd service
	cgroupPath, err := cgroups.GetOwnCgroup("name=systemd")
	if err != nil {
		log.G(ctx).WithError(err).Error("Failed to discover systemd cgroup path")
		return StatusRunError, err
	}

	// Set up the container spec. See `withSuperpowered` for conditional options
	// set when configured as superpowered.
	ctrOpts := containerd.WithNewSpec(
		oci.WithImageConfig(img),
		oci.WithHostNamespace(runtimespec.NetworkNamespace),
		oci.WithHostHostsFile,
		oci.WithHostResolvconf,
		// Launch the container under the systemd unit's cgroup
		oci.WithCgroup(cgroupPath),
		// Mount in the API socket for the Bottlerocket API server, and the API
		// client used to interact with it
		oci.WithMounts([]runtimespec.Mount{
			{
				Options:     []string{"bind", "rw"},
				Destination: "/run/api.sock",
				Source:      "/run/api.sock",
			},
			// Mount in the apiclient to make API calls to the Bottlerocket API server
			{
				Options:     []string{"bind", "ro"},
				Destination: "/usr/local/bin/apiclient",
				Source:      "/usr/bin/apiclient",
			},
			// Mount in the persistent storage location for this container
			{
				Options:     []string{"rbind", "rw"},
				Destination: "/.bottlerocket/host-containers/" + hc.ContainerID,
				Source:      "/local/host-containers/" + hc.ContainerID,
			}}),
		// Mount the rootfs with an SELinux label that makes it writable
		withMountLabel("system_u:object_r:local_t:s0"),
		// Include conditional options for superpowered containers.
		withSuperpowered(hc.Superpowered),
	)

	// Create and start the container.
	container, err := client.NewContainer(
		ctx,
		hc.ContainerID,
		containerd.WithImage(img),
		containerd.WithNewSnapshot(hc.ContainerID+"-snapshot", img),
		ctrOpts,
	)
	if err != nil {
		log.G(ctx).WithError(err).WithField("img", img.Name).Error("Failed to create container")
		return StatusRunError, err
	}
	defer func() {
		// Clean up the container as program wraps up.
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := container.Delete(cleanup, containerd.WithSnapshotCleanup)
		if err != nil {
			log.G(cleanup).WithError(err).Error("Failed to cleanup container")
		}
	}()

	// Create the container task
	task, err := container.NewTask(ctx, cio.NewCreator(cio.WithStdio))
	if err != nil {
		log.G(ctx).WithError(err).Error("Failed to create container task")
		return StatusRunError, err
	}
	defer func() {
		// Clean up the container's task as program wraps up.
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := task.Delete(cleanup)
		if err != nil {
			log.G(cleanup).WithError(err).Error("Failed to delete container task")
		}
	}()

	// Wait to call start in case the container task finishes too quickly.
	exitStatusC, err := task.Wait(context.TODO())
	if err != nil {
		log.G(ctx).WithError(err).Error("Unexpected error during container task setup.")
		return StatusRunError, err
	}

	// Execute the target container's task.
	if err := task.Start(ctx); err != nil {
		log.G(ctx).WithError(err).Error("Failed to start container task")
		return StatusRunError, err
	}
	log.G(ctx).Info("Successfully started container task")

	// Block until an OS signal (e.g. SIGTERM, SIGINT) is received or the
	// container task finishes and exits on its own.

	// Container task's exit status.
	var status containerd.ExitStatus
	// Context used when stopping and cleaning up the container task
	ctrCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	select {
	case <-ctx.Done():
		// SIGTERM the container task and get its exit status
		if err := task.Kill(ctrCtx, syscall.SIGTERM); err != nil {
			log.G(ctrCtx).WithError(err).Error("Failed to send SIGTERM to container")
			return StatusRunError, err
		}
		// Wait for 20 seconds and see check if container task exited
		const gracePeriod = 20 * time.Second
		timeout := time.NewTimer(gracePeriod)

		select {
		case status = <-exitStatusC:
			// Container task was able to exit on its own, stop the timer.
			if !timeout.Stop() {
				<-timeout.C
			}
		case <-timeout.C:
			// Container task still hasn't exited, SIGKILL the container task or
			// timeout and bail.

			const sigkillTimeout = 45 * time.Second
			killCtx, cancel := context.WithTimeout(ctrCtx, sigkillTimeout)

			err := task.Kill(killCtx, syscall.SIGKILL)
			cancel()
			if err != nil {
				log.G(ctrCtx).WithError(err).Error("Failed to SIGKILL container process, timed out")
				return StatusRunError, err
			}

			status = <-exitStatusC
		}
	case status = <-exitStatusC:
		// Container task exited on its own
	}
	code, _, err := status.Result()
	if err != nil {
		log.G(ctrCtx).WithError(err).Error("Failed to get container task exit status")
		return StatusRunError, err
	}
	log.G(ctrCtx).WithField("code", code).Info("Container task exited")

	return int(code), nil
}

func cancelOnSignal(ctx context.Context, cancel context.CancelFunc) {
	// Set up channel to handle signal notifications. We use a buffered channel
	// to avoid missing a signal.
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(c)

	for {
		select {
		case sig := <-c:
			log.G(ctx).Info("Received signal: ", sig)
			cancel()
		case <-ctx.Done():
			cancel()
			return
		}
	}

}

// deleteCtrIfExists cleans up an existing container. This involves killing its
// task then deleting it and its snapshot when any exist.
func deleteCtrIfExists(ctx context.Context, client *containerd.Client, targetCtr string) error {
	existingCtr, err := client.LoadContainer(ctx, targetCtr)
	if err != nil {
		if errdefs.IsNotFound(err) {
			log.G(ctx).WithField("ctr-id", targetCtr).Info("No clean up necessary, proceeding")
			return nil
		}
		log.G(ctx).WithField("ctr-id", targetCtr).WithError(err).Error("Failed to retrieve list of containers")
		return err
	}
	if existingCtr != nil {
		log.G(ctx).WithField("ctr-id", targetCtr).Info("Container already exists, deleting")
		// Kill task associated with existing container if it exists
		existingTask, err := existingCtr.Task(ctx, nil)
		if err != nil {
			// No associated task found, proceed to delete existing container
			if errdefs.IsNotFound(err) {
				log.G(ctx).WithField("ctr-id", targetCtr).Info("No task associated with existing container")
			} else {
				log.G(ctx).WithField("ctr-id", targetCtr).WithError(err).Error("Failed to retrieve task associated with existing container")
				return err
			}
		}
		if existingTask != nil {
			_, err := existingTask.Delete(ctx, containerd.WithProcessKill)
			if err != nil {
				log.G(ctx).WithField("ctr-id", targetCtr).WithError(err).Error("Failed to delete existing container task")
				return err
			}
			log.G(ctx).WithField("ctr-id", targetCtr).Info("Killed existing container task")
		}
		if err := existingCtr.Delete(ctx, containerd.WithSnapshotCleanup); err != nil {
			log.G(ctx).WithField("ctr-id", targetCtr).WithError(err).Error("Failed to delete existing container")
			return err
		}
		log.G(ctx).WithField("ctr-id", targetCtr).Info("Deleted existing container")
	}
	return nil
}

// withMountLabel configures the mount with the provided SELinux label.
func withMountLabel(label string) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *runtimespec.Spec) error {
		if s.Linux != nil {
			s.Linux.MountLabel = label
		}
		return nil
	}
}

// withSuperpowered add container options granting administrative privileges
// when it's `superpowered`.
func withSuperpowered(superpowered bool) oci.SpecOpts {
	if !superpowered {
		return oci.Compose(
			seccomp.WithDefaultProfile(),
		)
	}

	return oci.Compose(
		oci.WithHostNamespace(runtimespec.PIDNamespace),
		oci.WithParentCgroupDevices,
		oci.WithPrivileged,
		oci.WithNewPrivileges,
		oci.WithSelinuxLabel("system_u:system_r:super_t:s0"),
		oci.WithMounts([]runtimespec.Mount{
			{
				Options:     []string{"rbind", "ro"},
				Destination: "/.bottlerocket/rootfs",
				Source:      "/",
			},
			{
				Options:     []string{"rbind", "ro"},
				Destination: "/lib/modules",
				Source:      "/lib/modules",
			},
			{
				Options:     []string{"rbind", "ro"},
				Destination: "/usr/src/kernels",
				Source:      "/usr/src/kernels",
			},
			{
				Options:     []string{"rbind"},
				Destination: "/sys/kernel/debug",
				Source:      "/sys/kernel/debug",
			}}),
	)
}

// pullImage pulls an image from the specified source.
func pullImage(ctx context.Context, source string, client *containerd.Client) (containerd.Image, error) {
	// Retry with exponential backoff when failures occur, maximum retry
	// duration will not exceed 31 seconds.
	const maxRetryAttempts = 5
	const intervalMultiplier = 2
	const maxRetryInterval = 30 * time.Second
	const jitterPeakAmplitude = 4000
	const jitterLowerBound = 2000

	var retryInterval = 1 * time.Second
	var retryAttempts = 0
	var img containerd.Image
	for {
		var err error
		img, err = client.Pull(ctx, source,
			withDynamicResolver(ctx, source),
			containerd.WithSchema1Conversion)
		if err == nil {
			log.G(ctx).WithField("img", img.Name()).Info("Pulled successfully")
			break
		}

		// Check for errors that will not resolve with retries.

		for _, kind := range []error{
			// Reference errors - provided `source` is invalid in some way.
			reference.ErrHostnameRequired,
			reference.ErrInvalid,
			reference.ErrHostnameRequired,
			reference.ErrObjectRequired,
 		} {
			if errs.Is(err, kind) {
				log.G(ctx).
					WithField("source", source).
					WithError(err).
					Error("non-transient error, cannot pull image")
				return nil, err
			}
		}

		if retryAttempts >= maxRetryAttempts {
			return nil, errors.Wrap(err, "retries exhausted")
		}

		// Add a random jitter between 2 - 6 seconds to the retry interval
		retryIntervalWithJitter := retryInterval +
			time.Duration(jitterRand.Int31n(jitterPeakAmplitude))*time.Millisecond +
			jitterLowerBound*time.Millisecond

		log.G(ctx).WithError(err).Warnf("Failed to pull image. Waiting %s before retrying...", retryIntervalWithJitter)
		timer := time.NewTimer(retryIntervalWithJitter)
		select {
		case <-timer.C:
			retryInterval *= intervalMultiplier
			if retryInterval > maxRetryInterval {
				retryInterval = maxRetryInterval
			}
			retryAttempts++
		case <-ctx.Done():
			return nil, errors.Wrap(err, "context ended while retrying")
		}
	}

	log.G(ctx).WithField("img", img.Name()).Info("Unpacking...")
	if err := img.Unpack(ctx, containerd.DefaultSnapshotter); err != nil {
		return nil, errors.Wrap(err, "failed to unpack image")
	}

	return img, nil
}

// tagImage adds a tag to the image in containerd's metadata storage.
//
// Image tag logic derived from:
//
// https://github.com/containerd/containerd/blob/d80513ee8a6995bc7889c93e7858ddbbc51f063d/cmd/ctr/commands/images/tag.go#L67-L86
//
func tagImage(ctx context.Context, imageName string, newImageName string, client *containerd.Client) error {
	log.G(ctx).WithField("imageName", newImageName).Info("Tagging image")
	// Retrieve image information
	imageService := client.ImageService()
	image, err := imageService.Get(ctx, imageName)
	if err != nil {
		return err
	}
	// Tag with new image name
	image.Name = newImageName
	// Attempt to create the image first
	if _, err = imageService.Create(ctx, image); err != nil {
		// The image already exists then delete the original and attempt to create the new one
		if errdefs.IsAlreadyExists(err) {
			if err = imageService.Delete(ctx, newImageName); err != nil {
				return err
			}
			if _, err = imageService.Create(ctx, image); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	return nil
}

// withDynamicResolver provides an initialized resolver for use with ref.
func withDynamicResolver(ctx context.Context, ref string) containerd.RemoteOpt {
	if !strings.HasPrefix(ref, "ecr.aws/") {
		// not handled here
		return func(_ *containerd.Client, _ *containerd.RemoteContext) error { return nil }
	}

	return func(_ *containerd.Client, c *containerd.RemoteContext) error {
		// Create the ECR resolver
		resolver, err := ecr.NewResolver()
		if err != nil {
			return errors.Wrap(err, "Failed to create ECR resolver")
		}
		log.G(ctx).WithField("ref", ref).Info("Pulling with Amazon ECR Resolver")
		c.Resolver = resolver
		return nil
	}
}
