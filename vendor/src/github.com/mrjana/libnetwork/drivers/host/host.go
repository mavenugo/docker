package host

import (
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/sandbox"
	"github.com/docker/libnetwork/types"
)

const networkType = "host"

type driver struct{}

// New provides a new instance of host driver
func New() (string, driverapi.Driver) {
	return networkType, &driver{}
}

func (d *driver) Config(option map[string]interface{}) error {
	return nil
}

func (d *driver) CreateNetwork(id types.UUID, option map[string]interface{}) error {
	return nil
}

func (d *driver) DeleteNetwork(nid types.UUID) error {
	return nil
}

func (d *driver) CreateEndpoint(nid, eid types.UUID, epOptions map[string]interface{}) (*sandbox.Info, error) {
	return nil, nil
}

func (d *driver) DeleteEndpoint(nid, eid types.UUID) error {
	return nil
}

// Join method is invoked when a Sandbox is attached to an endpoint.
func (d *driver) Join(nid, eid types.UUID, sboxKey string, options map[string]interface{}) (*driverapi.JoinInfo, error) {
	jInfo := &driverapi.JoinInfo{
		SandboxKey:      sandbox.GenerateKey("host"),
		NoSandboxCreate: true,
		HostsPath:       "/etc/hosts",
	}

	return jInfo, nil
}

// Leave method is invoked when a Sandbox detaches from an endpoint.
func (d *driver) Leave(nid, eid types.UUID, options map[string]interface{}) error {
	return nil
}

func (d *driver) Type() string {
	return networkType
}
