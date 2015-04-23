package network

import "fmt"
import flag "github.com/docker/docker/pkg/mflag"

func (cli *NetworkCli) CmdDelete(chain string, args ...string) error {
	cmd := cli.Subcmd(chain, "delete", "<Network Name>", "Docker Network delete", true)
	fmt.Println("delete")
	cmd.Require(flag.Min, 1)
	cmd.ParseFlags(args, true)
	return nil
}
