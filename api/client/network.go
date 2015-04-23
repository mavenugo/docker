package client

import (
	"github.com/docker/docker/api/client/network"
	flag "github.com/docker/docker/pkg/mflag"
)

func (cli *DockerCli) CmdNetwork(args ...string) error {
	cmd := cli.Subcmd("network", "create | rm | attach | dettach", "Docker Network management", true)
	cmd.Require(flag.Min, 1)
	cmd.ParseFlags(args, false)

	nCli := network.NewNetworkCli(cli.out, cli.err, network.CallFunc(cli.call))
	return nCli.Cmd("docker network", args...)
}
