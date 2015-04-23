package network

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"strings"

	flag "github.com/docker/docker/pkg/mflag"
)

type CallFunc func(string, string, interface{}, map[string][]string) (io.ReadCloser, int, error)

type NetworkCli struct {
	out  io.Writer
	err  io.Writer
	call CallFunc
}

func NewNetworkCli(out, err io.Writer, call CallFunc) *NetworkCli {
	return &NetworkCli{
		out:  out,
		err:  err,
		call: call,
	}
}

func (cli *NetworkCli) getMethod(args ...string) (func(string, ...string) error, bool) {
	camelArgs := make([]string, len(args))
	for i, s := range args {
		if len(s) == 0 {
			return nil, false
		}
		camelArgs[i] = strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
	}
	methodName := "Cmd" + strings.Join(camelArgs, "")
	method := reflect.ValueOf(cli).MethodByName(methodName)
	if !method.IsValid() {
		return nil, false
	}
	return method.Interface().(func(string, ...string) error), true
}

func (cli *NetworkCli) Cmd(chain string, args ...string) error {
	if len(args) > 1 {
		method, exists := cli.getMethod(args[:2]...)
		if exists {
			return method(chain, args[2:]...)
		}
	}
	if len(args) > 0 {
		method, exists := cli.getMethod(args[0])
		if !exists {
			fmt.Fprintf(cli.err, "docker: '%s' is not a docker command. See 'docker --help'.\n", args[0])
			os.Exit(1)
		}
		return method(chain, args[1:]...)
	}
	return cli.CmdHelp()
}

func (cli *NetworkCli) Subcmd(chain, name, signature, description string, exitOnError bool) *flag.FlagSet {
	var errorHandling flag.ErrorHandling
	if exitOnError {
		errorHandling = flag.ExitOnError
	} else {
		errorHandling = flag.ContinueOnError
	}
	flags := flag.NewFlagSet(name, errorHandling)
	flags.Usage = func() {
		options := ""
		if signature != "" {
			signature = " " + signature
		}
		if flags.FlagCountUndeprecated() > 0 {
			options = " [OPTIONS]"
		}
		fmt.Fprintf(cli.out, "\nUsage: %s %s%s%s\n\n%s\n\n", chain, name, options, signature, description)
		flags.SetOutput(cli.out)
		flags.PrintDefaults()
		os.Exit(0)
	}
	return flags
}

func readBody(stream io.ReadCloser, statusCode int, err error) ([]byte, int, error) {
	if stream != nil {
		defer stream.Close()
	}
	if err != nil {
		return nil, statusCode, err
	}
	body, err := ioutil.ReadAll(stream)
	if err != nil {
		return nil, -1, err
	}
	return body, statusCode, nil
}
