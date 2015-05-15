package remote

import (
	"errors"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/plugins"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/sandbox"
	"github.com/docker/libnetwork/types"
)

var errNoCallback = errors.New("No Callback handler registered with Driver")

const remoteNetworkType = "remote"

type driver struct {
	callback    driverapi.DriverCallback
	endpoint    *plugins.Client
	networkType string
}

// Internal Convenience method to register a remote driver.
// The implementation of this method will change based on the dynamic driver registration design
func (d *driver) registerRemoteDriver(networkType string, client *plugins.Client) (driverapi.Driver, error) {
	newDriver := &driver{networkType: networkType, endpoint: client}
	if d.callback == nil {
		return nil, errNoCallback
	}
	if err := d.callback.RegisterDriver(networkType, newDriver); err != nil {
		return nil, err
	}
	return newDriver, nil
}

// Init does the necessary work to register remote drivers
func Init(dc driverapi.DriverCallback) error {
	d := &driver{}
	d.callback = dc
	plugins.Handle("Network-Driver", func(name string, client *plugins.Client) {
		logrus.Infof("New Network-Driver %s (%v) registered", name, client)
		// Handhake happens here with the Plugin and networkType managed by that plugin is determined.
		networkType := name
		d.registerRemoteDriver(networkType, client)
	})
	return nil
}

func (d *driver) Config(option map[string]interface{}) error {
	return driverapi.ErrNotImplemented
}

func (d *driver) CreateNetwork(id types.UUID, option map[string]interface{}) error {
	logrus.Infof("Successfully received CreateNetwork call for id=%s with Type=%s", id, d.networkType)
	return nil
}

func (d *driver) DeleteNetwork(nid types.UUID) error {
	return driverapi.ErrNotImplemented
}

func (d *driver) CreateEndpoint(nid, eid types.UUID, epOptions map[string]interface{}) (*sandbox.Info, error) {
	logrus.Infof("Successfully received CreateEndpoint call for id=%s/%s with Type=%s", nid, eid, d.networkType)
	return nil, nil
}

func (d *driver) DeleteEndpoint(nid, eid types.UUID) error {
	return driverapi.ErrNotImplemented
}

func (d *driver) EndpointInfo(nid, eid types.UUID) (map[string]interface{}, error) {
	return nil, driverapi.ErrNotImplemented
}

// Join method is invoked when a Sandbox is attached to an endpoint.
func (d *driver) Join(nid, eid types.UUID, sboxKey string, options map[string]interface{}) (*driverapi.JoinInfo, error) {
	return nil, driverapi.ErrNotImplemented
}

// Leave method is invoked when a Sandbox detaches from an endpoint.
func (d *driver) Leave(nid, eid types.UUID, options map[string]interface{}) error {
	return driverapi.ErrNotImplemented
}

func (d *driver) Type() string {
	return d.networkType
}
