package network

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)
import flag "github.com/docker/docker/pkg/mflag"

func (cli *NetworkCli) CmdCreate(chain string, args ...string) error {
	cmd := cli.Subcmd(chain, "create", "<Network Name>", "Docker Network create", true)
	cmd.Require(flag.Min, 1)
	cmd.ParseFlags(args, true)
	indented := new(bytes.Buffer)
	indented.WriteByte('[')
	for _, name := range cmd.Args() {
		// NOT A NETWORK CREATE CALL. borrowing cli.call from inspect
		obj, _, err := readBody(cli.call("GET", "/containers/"+name+"/json", nil, nil))
		if err != nil {
			fmt.Fprintf(cli.err, "%s", err)
			return err
		}
		if err = json.Indent(indented, obj, "", "    "); err != nil {
			fmt.Fprintf(cli.err, "%s\n", err)
			continue
		}
		indented.WriteString(",")
	}
	if indented.Len() > 1 {
		indented.Truncate(indented.Len() - 1)
	}
	indented.WriteString("]\n")

	if _, err := io.Copy(cli.out, indented); err != nil {
		return err
	}
	return nil
}
