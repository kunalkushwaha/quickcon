package cmd

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/docker/docker/cli"
	"github.com/docker/docker/reference"
	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
	containertype "github.com/docker/engine-api/types/container"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
)

type pullOptions struct {
	remote string
	all    bool
}

type createOptions struct {
	name string
}

// pullCmd represents the pull command
var pullCmd = &cobra.Command{
	Use:   "pull [OPTIONS] NAME[:TAG|@DIGEST]",
	Short: "Pull an image from a registry",
	Args:  cli.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var opts pullOptions
		opts.remote = args[0]
		runPull(opts)
	},
}

func init() {
	RootCmd.AddCommand(pullCmd)

	var opts pullOptions

	pullCmd.Flags().BoolVarP(&opts.all, "all-tags", "a", false, "Download all tagged images in the repository")

}

func runPull(opts pullOptions) error {
	dockerCli, _ := client.NewEnvClient()

	distributionRef, err := reference.ParseNamed(opts.remote)
	if err != nil {
		return err
	}
	if opts.all && !reference.IsNameOnly(distributionRef) {
		return errors.New("tag can't be used with --all-tags/-a")
	}

	if !opts.all && reference.IsNameOnly(distributionRef) {
		distributionRef = reference.WithDefaultTag(distributionRef)
		fmt.Printf("Using default tag: %s\n", reference.DefaultTag)
	}

	fmt.Println(distributionRef.String())

	privilegeFunc := func() (string, error) {
		return "IAmValid", nil
	}
	options := types.ImagePullOptions{RegistryAuth: "NotValid", PrivilegeFunc: privilegeFunc}
	resp, err := dockerCli.ImagePull(context.Background(), distributionRef.String(), options)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer resp.Close()
	_, err = ioutil.ReadAll(resp)
	if err != nil {
		fmt.Println(err)
		return err
	}

	// Create Container and export it.

	config := containertype.Config{
		Image: distributionRef.String(),
	}
	response, err := dockerCli.ContainerCreate(context.Background(), &config, nil, nil, "")
	if err != nil {
		fmt.Println(err)
		return err
	}

	fmt.Println("Intermediate container : ", response.ID)

	responseBody, err := dockerCli.ContainerExport(context.Background(), response.ID)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer responseBody.Close()
	body2, err := ioutil.ReadAll(responseBody)
	if err != nil {
		fmt.Println(err)
		return err
	}

	os.MkdirAll(distributionRef.Name(), 0777)
	base, _ := filepath.Abs(distributionRef.Name())
	tarball := filepath.Join(base, "/image.tar")
	target := filepath.Join(base, "rootfs")
	os.MkdirAll(target, 0777)

	ioutil.WriteFile(tarball, body2, 0777)
	err = untarCommand(tarball, target)
	if err != nil {
		fmt.Println(err)
		return err
	}

	err = dockerCli.ContainerRemove(context.Background(), response.ID, types.ContainerRemoveOptions{})
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println("Image successfuly downloaded")

	return nil
}

func untarCommand(tarball, target string) error {

	cmd := exec.Command("tar", "-C", target, "-xf", tarball)
	fmt.Println("Command Path ", cmd.Path)
	fmt.Println("Command Dir ", cmd.Dir)

	out, errr := cmd.CombinedOutput()
	fmt.Println(string(out))
	fmt.Println(errr)
	return nil
}

func untar(tarball, target string) error {
	reader, err := os.Open(tarball)
	if err != nil {
		return err
	}
	defer reader.Close()
	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Println(err)
			return err
		}

		path := filepath.Join(target, header.Name)
		info := header.FileInfo()

		if info.IsDir() {
			if err = os.MkdirAll(path, info.Mode()); err != nil {
				return err
			}
			continue
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, info.Mode())
		if err != nil {
			return err
		}
		_, err = io.Copy(file, tarReader)
		if err != nil {
			return err
		}
		file.Close()

	}
	return nil
}
