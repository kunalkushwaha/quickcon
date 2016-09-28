package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/kunalkushwaha/quickcon/cmd"
	"github.com/opencontainers/runc/libcontainer"
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()
		factory, err := libcontainer.New("")
		if err != nil {
			fmt.Printf("unable to initialize for container: %s", err)
			os.Exit(1)
		}
		if err := factory.StartInitialization(); err != nil {
			os.Exit(1)
		}
	}
}

func main() {
	cmd.Execute()
}
