package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

type runOpts struct {
	ID             string
	bundle         string
	console        string
	detach         bool
	pidFile        string
	noSubreaper    bool
	noPivot        bool
	noNewKeyring   bool
	systemdCgroups bool
	root           string
}

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "create and run a container",
	Run:   runCommand,
}

func init() {
	RootCmd.AddCommand(runCmd)

	runCmd.Flags().StringP("bundle", "b", "", "path to the root of the bundle directory, defaults to the current directory")
	runCmd.Flags().StringP("console", "", "", "specify the pty slave path for use with the container")
	runCmd.Flags().BoolP("detach", "d", false, "detach from the container's process")
	runCmd.Flags().StringP("pid-file", "", "", "specify the file to write the process id to")
	runCmd.Flags().BoolP("no-subreaper", "", false, "disable the use of the subreaper used to reap reparented processes")
	runCmd.Flags().BoolP("no-pivot", "", false, "do not use pivot root to jail process inside rootfs.  This should be used whenever the rootfs is on top of a ramdisk")
	runCmd.Flags().BoolP("no-new-keyring", "", false, "do not create a new session keyring for the container.  This will cause the container to inherit the calling processes session key")

}

func runCommand(cmd *cobra.Command, args []string) {

	opts := runOpts{}
	if len(args) < 1 {
		fmt.Println("container-id / Name required")
		cmd.Help()
		return
	}
	opts.ID = args[0]
	opts.bundle, _ = cmd.Flags().GetString("bundle")
	opts.console, _ = cmd.Flags().GetString("console")
	opts.detach, _ = cmd.Flags().GetBool("detach")
	opts.noNewKeyring, _ = cmd.Flags().GetBool("no-new-keyring")
	opts.noPivot, _ = cmd.Flags().GetBool("no-pivot")
	opts.noSubreaper, _ = cmd.Flags().GetBool("no-subreaper")
	opts.pidFile, _ = cmd.Flags().GetString("pid-file")
	opts.systemdCgroups, _ = cmd.PersistentFlags().GetBool("systemd-cgroup")
	opts.root, _ = cmd.PersistentFlags().GetString("root")

	spec, err := setupSpec(&opts)
	if err != nil {
		fmt.Println(err)
	}
	status, err := StartContainer(&opts, spec, false)
	if err == nil {
		// exit with the container's exit status so any external supervisor is
		// notified of the exit with the correct exit status.
		os.Exit(status)
	}
	fmt.Println(err)
}
