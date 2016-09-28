package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/go-systemd/activation"
	"github.com/kunalkushwaha/quickcon/librunc"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/cgroups/systemd"
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
	"github.com/opencontainers/runc/libcontainer/specconv"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const (
	specConfig = "config.json"
)

var errEmptyID = errors.New("container id cannot be empty")

var container libcontainer.Container

// setupSpec performs inital setup based on the cli.Context for the container
func setupSpec(opts *runOpts) (*specs.Spec, error) {
	bundle := opts.bundle
	if bundle != "" {
		if err := os.Chdir(bundle); err != nil {
			return nil, err
		}
	}
	spec, err := librunc.LoadSpec(specConfig)
	if err != nil {
		return nil, err
	}
	notifySocket := os.Getenv("NOTIFY_SOCKET")
	if notifySocket != "" {
		librunc.SetupSdNotify(spec, notifySocket)
	}
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("runc should be run as root")
	}
	return spec, nil
}

// StartContainer function
func StartContainer(opts *runOpts, spec *specs.Spec, create bool) (int, error) {
	id := opts.ID
	if id == "" {
		return -1, errEmptyID
	}
	container, err := CreateContainer(opts, id, spec)
	if err != nil {
		return -1, err
	}
	detach := opts.detach
	// Support on-demand socket activation by passing file descriptors into the container init process.
	listenFDs := []*os.File{}
	if os.Getenv("LISTEN_FDS") != "" {
		listenFDs = activation.Files(false)
	}
	r := &librunc.Runner{
		EnableSubreaper: !opts.noSubreaper,
		ShouldDestroy:   true,
		Container:       container,
		ListenFDs:       listenFDs,
		Console:         opts.console,
		Detach:          detach,
		PidFile:         opts.pidFile,
		Create:          create,
	}
	return r.Run(&spec.Process)
}

// LoadFactory returns the configured factory instance for execing containers.
func LoadFactory(opts *runOpts) (libcontainer.Factory, error) {
	root := opts.root
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	cgroupManager := libcontainer.Cgroupfs
	if opts.systemdCgroups {
		if systemd.UseSystemd() {
			cgroupManager = libcontainer.SystemdCgroups
		} else {
			return nil, fmt.Errorf("systemd cgroup flag passed, but systemd support for managing cgroups is not available")
		}
	}
	return libcontainer.New(abs, cgroupManager, libcontainer.CriuPath(opts.root))
}

/*
// GetContainer returns the specified container instance by loading it from state
// with the default factory.
func GetContainer(context *cli.Context) (libcontainer.Container, error) {
	id := context.Args().First()
	if id == "" {
		return nil, errEmptyID
	}
	factory, err := LoadFactory(context)
	if err != nil {
		return nil, err
	}
	return factory.Load(id)
}

func GetDefaultImagePath(context *cli.Context) string {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return filepath.Join(cwd, "checkpoint")
}
*/
func CreateContainer(opts *runOpts, id string, spec *specs.Spec) (libcontainer.Container, error) {
	config, err := specconv.CreateLibcontainerConfig(&specconv.CreateOpts{
		CgroupName:       id,
		UseSystemdCgroup: opts.systemdCgroups,
		NoPivotRoot:      opts.noPivot,
		NoNewKeyring:     opts.noNewKeyring,
		Spec:             spec,
	})
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(config.Rootfs); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("rootfs (%q) does not exist", config.Rootfs)
		}
		return nil, err
	}

	factory, err := LoadFactory(opts)
	if err != nil {
		return nil, err
	}
	return factory.Create(id, config)
}

// newProcess returns a new libcontainer Process with the arguments from the
// spec and stdio from the current process.
func newProcess(p specs.Process) (*libcontainer.Process, error) {
	lp := &libcontainer.Process{
		Args: p.Args,
		Env:  p.Env,
		// TODO: fix libcontainer's API to better support uid/gid in a typesafe way.
		User:            fmt.Sprintf("%d:%d", p.User.UID, p.User.GID),
		Cwd:             p.Cwd,
		Capabilities:    p.Capabilities,
		Label:           p.SelinuxLabel,
		NoNewPrivileges: &p.NoNewPrivileges,
		AppArmorProfile: p.ApparmorProfile,
	}
	for _, gid := range p.User.AdditionalGids {
		lp.AdditionalGroups = append(lp.AdditionalGroups, strconv.FormatUint(uint64(gid), 10))
	}
	for _, rlimit := range p.Rlimits {
		rl, err := librunc.CreateLibContainerRlimit(rlimit)
		if err != nil {
			return nil, err
		}
		lp.Rlimits = append(lp.Rlimits, rl)
	}
	return lp, nil
}

func dupStdio(process *libcontainer.Process, rootuid, rootgid int) error {
	process.Stdin = os.Stdin
	process.Stdout = os.Stdout
	process.Stderr = os.Stderr
	for _, fd := range []uintptr{
		os.Stdin.Fd(),
		os.Stdout.Fd(),
		os.Stderr.Fd(),
	} {
		if err := syscall.Fchown(int(fd), rootuid, rootgid); err != nil {
			return err
		}
	}
	return nil
}

// If systemd is supporting sd_notify protocol, this function will add support
// for sd_notify protocol from within the container.
func setupSdNotify(spec *specs.Spec, notifySocket string) {
	spec.Mounts = append(spec.Mounts, specs.Mount{Destination: notifySocket, Type: "bind", Source: notifySocket, Options: []string{"bind"}})
	spec.Process.Env = append(spec.Process.Env, fmt.Sprintf("NOTIFY_SOCKET=%s", notifySocket))
}

func destroy(container libcontainer.Container) {
	if err := container.Destroy(); err != nil {
		logrus.Error(err)
	}
}

// setupIO sets the proper IO on the process depending on the configuration
// If there is a nil error then there must be a non nil tty returned
func setupIO(process *libcontainer.Process, rootuid, rootgid int, console string, createTTY, detach bool) (*librunc.TTY, error) {
	// detach and createTty will not work unless a console path is passed
	// so error out here before changing any terminal settings
	if createTTY && detach && console == "" {
		return nil, fmt.Errorf("cannot allocate tty if runc will detach")
	}
	if createTTY {
		return librunc.CreateTty(process, rootuid, rootgid, console)
	}
	if detach {
		if err := librunc.DupStdio(process, rootuid, rootgid); err != nil {
			return nil, err
		}
		return &librunc.TTY{}, nil
	}
	return librunc.CreateStdioPipes(process, rootuid, rootgid)
}

// createPidFile creates a file with the processes pid inside it atomically
// it creates a temp file with the paths filename + '.' infront of it
// then renames the file
func createPidFile(path string, process *libcontainer.Process) error {
	pid, err := process.Pid()
	if err != nil {
		return err
	}
	var (
		tmpDir  = filepath.Dir(path)
		tmpName = filepath.Join(tmpDir, fmt.Sprintf(".%s", filepath.Base(path)))
	)
	f, err := os.OpenFile(tmpName, os.O_RDWR|os.O_CREATE|os.O_EXCL|os.O_SYNC, 0666)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "%d", pid)
	f.Close()
	if err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
