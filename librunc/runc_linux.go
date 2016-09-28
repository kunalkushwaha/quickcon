// +build linux

package librunc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func fatalf(t string, v ...interface{}) {
	fmt.Printf(t, v...)
	os.Exit(1)
}

// NewProcess returns a new libcontainer Process with the arguments from the
// spec and stdio from the current process.
func NewProcess(p specs.Process) (*libcontainer.Process, error) {
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
		rl, err := createLibContainerRlimit(rlimit)
		if err != nil {
			return nil, err
		}
		lp.Rlimits = append(lp.Rlimits, rl)
	}
	return lp, nil
}

func DupStdio(process *libcontainer.Process, rootuid, rootgid int) error {
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
func SetupSdNotify(spec *specs.Spec, notifySocket string) {
	spec.Mounts = append(spec.Mounts, specs.Mount{Destination: notifySocket, Type: "bind", Source: notifySocket, Options: []string{"bind"}})
	spec.Process.Env = append(spec.Process.Env, fmt.Sprintf("NOTIFY_SOCKET=%s", notifySocket))
}

func Destroy(container libcontainer.Container) {
	if err := container.Destroy(); err != nil {
		logrus.Error(err)
	}
}

// SetupIO sets the proper IO on the process depending on the configuration
// If there is a nil error then there must be a non nil tty returned
func SetupIO(process *libcontainer.Process, rootuid, rootgid int, console string, createTTY, detach bool) (*TTY, error) {
	// detach and createTty will not work unless a console path is passed
	// so error out here before changing any terminal settings
	if createTTY && detach && console == "" {
		return nil, fmt.Errorf("cannot allocate tty if runc will detach")
	}
	if createTTY {
		return CreateTty(process, rootuid, rootgid, console)
	}
	if detach {
		if err := DupStdio(process, rootuid, rootgid); err != nil {
			return nil, err
		}
		return &TTY{}, nil
	}
	return CreateStdioPipes(process, rootuid, rootgid)
}

// CreatePidFile creates a file with the processes pid inside it atomically
// it creates a temp file with the paths filename + '.' infront of it
// then renames the file
func CreatePidFile(path string, process *libcontainer.Process) error {
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

type Runner struct {
	EnableSubreaper bool
	ShouldDestroy   bool
	Detach          bool
	ListenFDs       []*os.File
	PidFile         string
	Console         string
	Container       libcontainer.Container
	Create          bool
}

func (r *Runner) Run(config *specs.Process) (int, error) {
	process, err := NewProcess(*config)
	if err != nil {
		r.Destroy()
		return -1, err
	}
	if len(r.ListenFDs) > 0 {
		process.Env = append(process.Env, fmt.Sprintf("LISTEN_FDS=%d", len(r.ListenFDs)), "LISTEN_PID=1")
		process.ExtraFiles = append(process.ExtraFiles, r.ListenFDs...)
	}
	rootuid, err := r.Container.Config().HostUID()
	if err != nil {
		r.Destroy()
		return -1, err
	}
	rootgid, err := r.Container.Config().HostGID()
	if err != nil {
		r.Destroy()
		return -1, err
	}
	tty, err := SetupIO(process, rootuid, rootgid, r.Console, config.Terminal, r.Detach || r.Create)
	if err != nil {
		r.Destroy()
		return -1, err
	}
	handler := NewSignalHandler(tty, r.EnableSubreaper)
	startFn := r.Container.Start
	if !r.Create {
		startFn = r.Container.Run
	}
	defer tty.Close()
	if err := startFn(process); err != nil {
		r.Destroy()
		return -1, err
	}
	if err := tty.ClosePostStart(); err != nil {
		r.Terminate(process)
		r.Destroy()
		return -1, err
	}
	if r.PidFile != "" {
		if err := CreatePidFile(r.PidFile, process); err != nil {
			r.Terminate(process)
			r.Destroy()
			return -1, err
		}
	}
	if r.Detach || r.Create {
		return 0, nil
	}
	status, err := handler.Forward(process)
	if err != nil {
		r.Terminate(process)
	}
	r.Destroy()
	return status, err
}

func (r *Runner) Destroy() {
	if r.ShouldDestroy {
		Destroy(r.Container)
	}
}

func (r *Runner) Terminate(p *libcontainer.Process) {
	p.Signal(syscall.SIGKILL)
	p.Wait()
}

func ValidateProcessSpec(spec *specs.Process) error {
	if spec.Cwd == "" {
		return fmt.Errorf("Cwd property must not be empty")
	}
	if !filepath.IsAbs(spec.Cwd) {
		return fmt.Errorf("Cwd must be an absolute path")
	}
	if len(spec.Args) == 0 {
		return fmt.Errorf("args must not be empty")
	}
	return nil
}

func sPtr(s string) *string      { return &s }
func rPtr(r rune) *rune          { return &r }
func iPtr(i int64) *int64        { return &i }
func u32Ptr(i int64) *uint32     { u := uint32(i); return &u }
func fmPtr(i int64) *os.FileMode { fm := os.FileMode(i); return &fm }

// loadSpec loads the specification from the provided path.
func LoadSpec(cPath string) (spec *specs.Spec, err error) {
	cf, err := os.Open(cPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("JSON specification file %s not found", cPath)
		}
		return nil, err
	}
	defer cf.Close()

	if err = json.NewDecoder(cf).Decode(&spec); err != nil {
		return nil, err
	}
	return spec, ValidateProcessSpec(&spec.Process)
}

func createLibContainerRlimit(rlimit specs.Rlimit) (configs.Rlimit, error) {
	rl, err := strToRlimit(rlimit.Type)
	if err != nil {
		return configs.Rlimit{}, err
	}
	return configs.Rlimit{
		Type: rl,
		Hard: uint64(rlimit.Hard),
		Soft: uint64(rlimit.Soft),
	}, nil
}
