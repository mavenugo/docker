// +build experimental

package main

import (
	"os/exec"
	"strings"

	"github.com/integr/vendor/src/github.com/go-check/check"
)

func assertCntIsAvailable(c *check.C, sname, name string) {
	if !isSrvPresent(c, sname, name) {
		c.Fatalf("Container %s attached to service %s on network %s not found in service ls o/p", sname, name)
	}
}

func assertCntNotAvailable(c *check.C, sname, name string) {
	if isSrvPresent(c, sname, name) {
		c.Fatalf("Found container %s attached to %s on network %s in service ls o/p", cname, sname, name)
	}
}

func assertSrvIsAvailable(c *check.C, sname, name string) {
	if !isSrvPresent(c, sname, name) {
		c.Fatalf("Service %s on network %s not found in service ls o/p", sname, name)
	}
}

func assertSrvNotAvailable(c *check.C, sname, name string) {
	if isSrvPresent(c, sname, name) {
		c.Fatalf("Found service %s on network %s in service ls o/p", sname, name)
	}
}

func isSrvPresent(c *check.C, sname, name string) {
	runCmd := exec.Command(dockerBinary, "service", "ls")
	out, _, _, err := runCommandWithStdoutStderr(runCmd)
	c.Assert(err, check.IsNil)
	lines := strings.Split(out, "\n")
	for i := 1; i < len(lines)-1; i++ {
		if strings.Contains(lines[i], sname) && strings.Contains(lines[i], name) {
			return true
		}
	}
	return false
}

func isCntPresent(c *check.C, cname, sname, name string) {
	runCmd := exec.Command(dockerBinary, "service", "ls")
	out, _, _, err := runCommandWithStdoutStderr(runCmd)
	c.Assert(err, check.IsNil)
	lines := strings.Split(out, "\n")
	for i := 1; i < len(lines)-1; i++ {
		if strings.Contains(lines[i], name) && strings.Contains(lines[i], sname) && strings.Contains(lines[i], cname) {
			return true
		}
	}
	return false
}

func (s *DockerSuite) TestDockerServiceCreateDelete(c *check.C) {
	runCmd := exec.Command(dockerBinary, "network", "create", "test")
	out, _, _, err := runCommandWithStdoutStderr(runCmd)
	c.Assert(err, check.IsNil)
	assertNwIsAvailable(c, "test")

	runCmd = exec.Command(dockerBinary, "service", "publish", "s1.test")
	out, _, _, err = runCommandWithStdoutStderr(runCmd)
	c.Assert(err, check.IsNil)
	assertSrvIsAvailable(c, "s1", "test")

	runCmd = exec.Command(dockerBinary, "service", "unpublish", "s1.test")
	out, _, _, err = runCommandWithStdoutStderr(runCmd)
	c.Assert(err, check.IsNil)
	assertSrvNotAvailable(c, "s1", "test")

	runCmd = exec.Command(dockerBinary, "network", "rm", "test")
	out, _, _, err = runCommandWithStdoutStderr(runCmd)
	c.Assert(err, check.IsNil)
	assertNwNotAvailable(c, "test")
}

func (s *DockerSuite) TestDockerPublishServiceFlag(c *check.C) {
	// Run saying the container is the backend for the specified service on the specified network
	runCmd := exec.Command(dockerBinary, "run", "-d", "--expose=23", "-publish-service", "telnet.production", "busybox")
	out, _, err := runCommandWithOutput(runCmd)
	c.Assert(err, check.IsNil)
	cid := strings.TrimSpace(out)

	// Verify container is attached in service ps o/p
	runCmd := exec.Command(dockerBinary, "service", "ls", "--no-trunc")
	out, _, err := runCommandWithOutput(runCmd)
	c.Assert(err, check.IsNil)
	assertCntIsAvailable(c, cid, "telnet", "production")

	// Detach the backend
	runCmd := exec.Command(dockerBinary, "service", "detach", cid, "telnet")
	out, _, err := runCommandWithOutput(runCmd)
	c.Assert(err, check.IsNil)
	assertCntNotAvailable(c, cid, "telnet", "production")
}
