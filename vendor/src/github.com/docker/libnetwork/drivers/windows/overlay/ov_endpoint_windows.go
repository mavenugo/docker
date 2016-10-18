package overlay

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/Microsoft/hcsshim"
	"github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/types"
)

type endpointTable map[string]*endpoint

const overlayEndpointPrefix = "overlay/endpoint"

type endpoint struct {
	id        string
	nid       string
	profileId string
	ifName    string
	mac       net.HardwareAddr
	addr      *net.IPNet
	dbExists  bool
	dbIndex   uint64
}

func (n *network) endpoint(eid string) *endpoint {

	logrus.Info("WINOVERLAY: Enter endpoint")

	n.Lock()
	defer n.Unlock()

	return n.endpoints[eid]
}

func (n *network) addEndpoint(ep *endpoint) {

	logrus.Info("WINOVERLAY: Enter addEndpoint")

	n.Lock()
	n.endpoints[ep.id] = ep
	n.Unlock()
}

func (n *network) deleteEndpoint(eid string) {

	logrus.Info("WINOVERLAY: Enter deleteEndpoint")

	n.Lock()
	delete(n.endpoints, eid)
	n.Unlock()
}

func (d *driver) CreateEndpoint(nid, eid string, ifInfo driverapi.InterfaceInfo,
	epOptions map[string]interface{}) error {
	var err error

	logrus.Info("WINOVERLAY: Enter CreateEndpoint")

	if err = validateID(nid, eid); err != nil {
		return err
	}

	// Since we perform lazy configuration make sure we try
	// configuring the driver when we enter CreateEndpoint since
	// CreateNetwork may not be called in every node.
	if err := d.configure(); err != nil {
		return err
	}

	n := d.network(nid)
	if n == nil {
		return fmt.Errorf("network id %q not found", nid)
	}

	logrus.Info("WINOVERLAY: CreateEndpoint creating endpoint object")

	ep := &endpoint{
		id:   eid,
		nid:  n.id,
		addr: ifInfo.Address(),
		mac:  ifInfo.MacAddress(),
	}

	logrus.Infof("WINOVERLAY: CreateEndpoint endpoint address is %s", ep.addr)

	if ep.addr == nil {
		return fmt.Errorf("create endpoint was not passed interface IP address")
	}

	logrus.Info("WINOVERLAY: CreateEndpoint Locating subnet for endpoint")

	if s := n.getSubnetforIP(ep.addr); s == nil {
		return fmt.Errorf("no matching subnet for IP %q in network %q\n", ep.addr, nid)
	}

	logrus.Info("WINOVERLAY: CreateEndpoint checking on MAC")

	// Not doing this for now as current plan is to let HNS assign the MAC
	//if ep.mac == nil {

	//logrus.Info("WINOVERLAY: CreateEndpoint generating a MAC")

	//ep.mac = netutils.GenerateMACFromIP(ep.addr.IP)
	//if err := ifInfo.SetMacAddress(ep.mac); err != nil {
	//	return err
	//}
	//}

	// Todo: Add port bindings and qos policies here

	logrus.Info("WINOVERLAY: CreateEndpoint notifying HNS of the local endpoint")

	hnsEndpoint := &hcsshim.HNSEndpoint{
		VirtualNetwork:  n.hnsId,
		IPAddress:       ep.addr.IP,
		IsLocalEndpoint: true,
	}

	if ep.mac != nil {
		hnsEndpoint.MacAddress = ep.mac.String()
	}

	paPolicy, err := json.Marshal(hcsshim.PaPolicy{
		Type: "PA",
		PA:   n.providerAddress,
	})

	if err != nil {
		return err
	}

	hnsEndpoint.Policies = append(hnsEndpoint.Policies, paPolicy)

	configurationb, err := json.Marshal(hnsEndpoint)
	if err != nil {
		return err
	}

	configuration := string(configurationb)
	logrus.Infof("HNSEndpoint Request =%v", configuration)

	hnsresponse, err := hcsshim.HNSEndpointRequest("POST", "", string(configurationb))
	if err != nil {
		return err
	}

	ep.profileId = hnsresponse.Id

	if ep.mac == nil {
		ep.mac, err = net.ParseMAC(hnsresponse.MacAddress)
		if err != nil {
			return err
		}

		if err := ifInfo.SetMacAddress(ep.mac); err != nil {
			return err
		}
	}

	logrus.Info("WINOVERLAY: CreateEndpoint adding the endpoint to the network")

	n.addEndpoint(ep)

	logrus.Info("WINOVERLAY: CreateEndpoint writing endpoint to local store")

	if err := d.writeEndpointToStore(ep); err != nil {
		return fmt.Errorf("failed to update overlay endpoint %s to local store: %v", ep.id[0:7], err)
	}

	logrus.Info("WINOVERLAY: Leaving CreateEndpoint")

	return nil
}

func (d *driver) DeleteEndpoint(nid, eid string) error {

	logrus.Info("WINOVERLAY: Enter DeleteEndpoint")

	if err := validateID(nid, eid); err != nil {
		return err
	}

	n := d.network(nid)
	if n == nil {
		return fmt.Errorf("network id %q not found", nid)
	}

	ep := n.endpoint(eid)
	if ep == nil {
		return fmt.Errorf("endpoint id %q not found", eid)
	}

	n.deleteEndpoint(eid)

	if err := d.deleteEndpointFromStore(ep); err != nil {
		logrus.Warnf("Failed to delete overlay endpoint %s from local store: %v", ep.id[0:7], err)
	}

	logrus.Infof("HNSEndpoint Request DELETE for endpoint id %s", ep.profileId)

	_, err := hcsshim.HNSEndpointRequest("DELETE", ep.profileId, "")
	if err != nil {
		return err
	}

	return nil
}

func (d *driver) EndpointOperInfo(nid, eid string) (map[string]interface{}, error) {
	if err := validateID(nid, eid); err != nil {
		return nil, err
	}

	n := d.network(nid)
	if n == nil {
		return nil, fmt.Errorf("network id %q not found", nid)
	}

	ep := n.endpoint(eid)
	if ep == nil {
		return nil, fmt.Errorf("endpoint id %q not found", eid)
	}

	data := make(map[string]interface{}, 1)
	data["hnsid"] = ep.profileId
	return data, nil
}

func (d *driver) deleteEndpointFromStore(e *endpoint) error {

	logrus.Info("WINOVERLAY: Enter deleteEndpointFromStore")

	if d.localStore == nil {
		return fmt.Errorf("overlay local store not initialized, ep not deleted")
	}

	if err := d.localStore.DeleteObjectAtomic(e); err != nil {
		return err
	}

	return nil
}

func (d *driver) writeEndpointToStore(e *endpoint) error {

	logrus.Info("WINOVERLAY: Enter writeEndpointToStore")

	if d.localStore == nil {
		return fmt.Errorf("overlay local store not initialized, ep not added")
	}

	if err := d.localStore.PutObjectAtomic(e); err != nil {
		return err
	}
	return nil
}

func (ep *endpoint) DataScope() string {
	return datastore.LocalScope
}

func (ep *endpoint) New() datastore.KVObject {
	return &endpoint{}
}

func (ep *endpoint) CopyTo(o datastore.KVObject) error {
	dstep := o.(*endpoint)
	*dstep = *ep
	return nil
}

func (ep *endpoint) Key() []string {
	return []string{overlayEndpointPrefix, ep.id}
}

func (ep *endpoint) KeyPrefix() []string {
	return []string{overlayEndpointPrefix}
}

func (ep *endpoint) Index() uint64 {
	return ep.dbIndex
}

func (ep *endpoint) SetIndex(index uint64) {
	ep.dbIndex = index
	ep.dbExists = true
}

func (ep *endpoint) Exists() bool {
	return ep.dbExists
}

func (ep *endpoint) Skip() bool {
	return false
}

func (ep *endpoint) Value() []byte {
	b, err := json.Marshal(ep)
	if err != nil {
		return nil
	}
	return b
}

func (ep *endpoint) SetValue(value []byte) error {
	return json.Unmarshal(value, ep)
}

func (ep *endpoint) MarshalJSON() ([]byte, error) {

	logrus.Info("WINOVERLAY: Enter MarshalJSON")

	epMap := make(map[string]interface{})

	epMap["id"] = ep.id
	epMap["nid"] = ep.nid
	if ep.profileId != "" {
		epMap["profileId"] = ep.profileId
	}
	if ep.ifName != "" {
		epMap["ifName"] = ep.ifName
	}
	if ep.addr != nil {
		epMap["addr"] = ep.addr.String()
	}
	if len(ep.mac) != 0 {
		epMap["mac"] = ep.mac.String()
	}

	return json.Marshal(epMap)
}

func (ep *endpoint) UnmarshalJSON(value []byte) error {
	var (
		err   error
		epMap map[string]interface{}
	)

	logrus.Info("WINOVERLAY: Enter UnmarshalJSON")

	json.Unmarshal(value, &epMap)

	ep.id = epMap["id"].(string)
	ep.nid = epMap["nid"].(string)
	if v, ok := epMap["profileId"]; ok {
		ep.profileId = v.(string)
	}
	if v, ok := epMap["mac"]; ok {
		if ep.mac, err = net.ParseMAC(v.(string)); err != nil {
			return types.InternalErrorf("failed to decode endpoint interface mac address after json unmarshal: %s", v.(string))
		}
	}
	if v, ok := epMap["addr"]; ok {
		if ep.addr, err = types.ParseCIDR(v.(string)); err != nil {
			return types.InternalErrorf("failed to decode endpoint interface ipv4 address after json unmarshal: %v", err)
		}
	}
	if v, ok := epMap["ifName"]; ok {
		ep.ifName = v.(string)
	}

	return nil
}
