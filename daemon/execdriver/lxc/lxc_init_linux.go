// +build linux

package lxc

import (
	"fmt"
	"os"

	"github.com/docker/libcontainer/utils"
	"github.com/vishvananda/netns"
)

func finalizeNamespace(args *InitArgs) error {
	if err := utils.CloseExecFrom(3); err != nil {
		return err
	}

	// Make sure you setup the netns before you setup user since once you
	// setup as a unprivileged used you cannot set into different namespace.
	if args.NetNsPath != "" {
		f, err := os.OpenFile(args.NetNsPath, os.O_RDONLY, 0)
		if err != nil {
			return fmt.Errorf("failed get network namespace %q: %v", args.NetNsPath, err)
		}
		defer f.Close()

		nsFD := f.Fd()
		if err = netns.Set(netns.NsHandle(nsFD)); err != nil {
			return err
		}
	}

	if err := setupUser(args.User); err != nil {
		return fmt.Errorf("setup user %s", err)
	}
	if err := setupWorkingDirectory(args); err != nil {
		return err
	}

	return nil
}
