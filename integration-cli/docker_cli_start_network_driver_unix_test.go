// +build !windows

package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"

	"github.com/go-check/check"
)

func init() {
	check.Suite(&ExternalNetworkSuite{
		ds: &DockerSuite{},
	})
}

type ExternalNetworkSuite struct {
	server *httptest.Server
	ds     *DockerSuite
}

func (s *ExternalNetworkSuite) SetUpTest(c *check.C) {
	s.ds.SetUpTest(c)
}

func (s *ExternalNetworkSuite) TearDownTest(c *check.C) {
	s.ds.TearDownTest(c)
}

func (s *ExternalNetworkSuite) SetUpSuite(c *check.C) {
	mux := http.NewServeMux()
	s.server = httptest.NewServer(mux)

	type pluginRequest struct {
		name string
	}

	mux.HandleFunc("/Plugin.Activate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "appplication/vnd.docker.plugins.v1+json")
		fmt.Fprintln(w, `{"Implements": ["Network-Driver"]}`)
	})

	if err := os.MkdirAll("/usr/share/docker/plugins", 0755); err != nil {
		c.Fatal(err)
	}

	if err := ioutil.WriteFile("/usr/share/docker/plugins/test-external-network-driver.spec", []byte(s.server.URL), 0644); err != nil {
		c.Fatal(err)
	}
}

func (s *ExternalNetworkSuite) TearDownSuite(c *check.C) {
	s.server.Close()

	if err := os.RemoveAll("/usr/share/docker/plugins"); err != nil {
		c.Fatal(err)
	}
}

func (s *ExternalNetworkSuite) TestStartExternalNetworkDriver(c *check.C) {
	runCmd := exec.Command(dockerBinary, "run", "--name", "test-data", "--net=test-external-network-driver:test", "busybox:latest", "ls")
	out, stderr, exitCode, err := runCommandWithStdoutStderr(runCmd)
	if err != nil && exitCode != 0 {
		c.Fatal(out, stderr, err)
	}
}
