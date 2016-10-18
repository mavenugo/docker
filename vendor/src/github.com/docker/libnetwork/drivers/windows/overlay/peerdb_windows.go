package overlay

import (
	"fmt"
	"net"
	"sync"

	"encoding/json"
	log "github.com/Sirupsen/logrus"

	"github.com/Microsoft/hcsshim"
	"github.com/docker/libnetwork/types"
)

const ovPeerTable = "overlay_peer_table"

type peerKey struct {
	peerIP  net.IP
	peerMac net.HardwareAddr
}

type peerEntry struct {
	eid        string
	vtep       net.IP
	peerIPMask net.IPMask
	inSandbox  bool
	isLocal    bool
}

type peerMap struct {
	mp map[string]peerEntry
	sync.Mutex
}

type peerNetworkMap struct {
	mp map[string]*peerMap
	sync.Mutex
}

func (pKey peerKey) String() string {
	return fmt.Sprintf("%s %s", pKey.peerIP, pKey.peerMac)
}

func (pKey *peerKey) Scan(state fmt.ScanState, verb rune) error {
	ipB, err := state.Token(true, nil)
	if err != nil {
		return err
	}

	pKey.peerIP = net.ParseIP(string(ipB))

	macB, err := state.Token(true, nil)
	if err != nil {
		return err
	}

	pKey.peerMac, err = net.ParseMAC(string(macB))
	if err != nil {
		return err
	}

	return nil
}

var peerDbWg sync.WaitGroup

func (d *driver) peerDbWalk(f func(string, *peerKey, *peerEntry) bool) error {
	d.peerDb.Lock()
	nids := []string{}
	for nid := range d.peerDb.mp {
		nids = append(nids, nid)
	}
	d.peerDb.Unlock()

	for _, nid := range nids {
		d.peerDbNetworkWalk(nid, func(pKey *peerKey, pEntry *peerEntry) bool {
			return f(nid, pKey, pEntry)
		})
	}
	return nil
}

func (d *driver) peerDbNetworkWalk(nid string, f func(*peerKey, *peerEntry) bool) error {
	d.peerDb.Lock()
	pMap, ok := d.peerDb.mp[nid]
	if !ok {
		d.peerDb.Unlock()
		return nil
	}
	d.peerDb.Unlock()

	pMap.Lock()
	for pKeyStr, pEntry := range pMap.mp {
		var pKey peerKey
		if _, err := fmt.Sscan(pKeyStr, &pKey); err != nil {
			log.Warnf("Peer key scan on network %s failed: %v", nid, err)
		}

		if f(&pKey, &pEntry) {
			pMap.Unlock()
			return nil
		}
	}
	pMap.Unlock()

	return nil
}

func (d *driver) peerDbSearch(nid string, peerIP net.IP) (net.HardwareAddr, net.IPMask, net.IP, error) {
	var (
		peerMac    net.HardwareAddr
		vtep       net.IP
		peerIPMask net.IPMask
		found      bool
	)

	err := d.peerDbNetworkWalk(nid, func(pKey *peerKey, pEntry *peerEntry) bool {
		if pKey.peerIP.Equal(peerIP) {
			peerMac = pKey.peerMac
			peerIPMask = pEntry.peerIPMask
			vtep = pEntry.vtep
			found = true
			return found
		}

		return found
	})

	if err != nil {
		return nil, nil, nil, fmt.Errorf("peerdb search for peer ip %q failed: %v", peerIP, err)
	}

	if !found {
		return nil, nil, nil, fmt.Errorf("peer ip %q not found in peerdb", peerIP)
	}

	return peerMac, peerIPMask, vtep, nil
}

func (d *driver) peerDbAdd(nid, eid string, peerIP net.IP, peerIPMask net.IPMask,
	peerMac net.HardwareAddr, vtep net.IP, isLocal bool) {

	peerDbWg.Wait()

	d.peerDb.Lock()
	pMap, ok := d.peerDb.mp[nid]
	if !ok {
		d.peerDb.mp[nid] = &peerMap{
			mp: make(map[string]peerEntry),
		}

		pMap = d.peerDb.mp[nid]
	}
	d.peerDb.Unlock()

	pKey := peerKey{
		peerIP:  peerIP,
		peerMac: peerMac,
	}

	pEntry := peerEntry{
		eid:        eid,
		vtep:       vtep,
		peerIPMask: peerIPMask,
		isLocal:    isLocal,
	}

	pMap.Lock()
	pMap.mp[pKey.String()] = pEntry
	pMap.Unlock()
}

func (d *driver) peerDbDelete(nid, eid string, peerIP net.IP, peerIPMask net.IPMask,
	peerMac net.HardwareAddr, vtep net.IP) {
	peerDbWg.Wait()

	d.peerDb.Lock()
	pMap, ok := d.peerDb.mp[nid]
	if !ok {
		d.peerDb.Unlock()
		return
	}
	d.peerDb.Unlock()

	pKey := peerKey{
		peerIP:  peerIP,
		peerMac: peerMac,
	}

	pMap.Lock()
	delete(pMap.mp, pKey.String())
	pMap.Unlock()
}

func (d *driver) peerDbUpdateSandbox(nid string) {
	d.peerDb.Lock()
	pMap, ok := d.peerDb.mp[nid]
	if !ok {
		d.peerDb.Unlock()
		return
	}
	d.peerDb.Unlock()

	peerDbWg.Add(1)

	var peerOps []func()
	pMap.Lock()
	for pKeyStr, pEntry := range pMap.mp {
		var pKey peerKey
		if _, err := fmt.Sscan(pKeyStr, &pKey); err != nil {
			fmt.Printf("peer key scan failed: %v", err)
		}

		if pEntry.isLocal {
			continue
		}

		// Go captures variables by reference. The pEntry could be
		// pointing to the same memory location for every iteration. Make
		// a copy of pEntry before capturing it in the following closure.
		entry := pEntry
		op := func() {
			if err := d.peerAdd(nid, entry.eid, pKey.peerIP, entry.peerIPMask,
				pKey.peerMac, entry.vtep,
				false); err != nil {
				fmt.Printf("peerdbupdate in sandbox failed for ip %s and mac %s: %v",
					pKey.peerIP, pKey.peerMac, err)
			}
		}

		peerOps = append(peerOps, op)
	}
	pMap.Unlock()

	for _, op := range peerOps {
		op()
	}

	peerDbWg.Done()
}

func (d *driver) pushLocalDb() {

	log.Info("WINOVERLAY: Enter pushLocalDb")

	d.peerDbWalk(func(nid string, pKey *peerKey, pEntry *peerEntry) bool {
		if pEntry.isLocal {
			d.pushLocalEndpointEvent("join", nid, pEntry.eid)
		}
		return false
	})
}

func (d *driver) peerAdd(nid, eid string, peerIP net.IP, peerIPMask net.IPMask,
	peerMac net.HardwareAddr, vtep net.IP, updateDb bool) error {

	log.Infof("WINOVERLAY: Enter peerAdd for ca ip %s with ca mac %s", peerIP.String(), peerMac.String())

	if err := validateID(nid, eid); err != nil {
		return err
	}

	n := d.network(nid)
	if n == nil {
		return nil
	}

	if updateDb {

		log.Info("WINOVERLAY: peerAdd: notifying HNS of the REMOTE endpoint")

		hnsEndpoint := &hcsshim.HNSEndpoint{
			VirtualNetwork:  n.hnsId,
			MacAddress:      peerMac.String(),
			IPAddress:       peerIP,
			IsLocalEndpoint: false,
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
		log.Infof("HNSEndpoint Request =%v", configuration)

		hnsresponse, err := hcsshim.HNSEndpointRequest("POST", "", string(configurationb))
		if err != nil {
			return err
		}

		log.Infof("WINOVERLAY: PeerAdd: Updating DB for peerIP %s using PA %s", peerIP.String(), n.providerAddress)
		d.peerDbAdd(nid, eid, peerIP, peerIPMask, peerMac, net.ParseIP(n.providerAddress), false)

		// Temp: We have to create a endpoint object to keep track of the HNS ID for
		// this endpoint so that we can retrieve it later when the endpoint is deleted.
		// This seems unnecessary when we already have dockers EID. See if we can pass
		// the global EID to HNS to use as it's ID, rather than having each HNS assign
		// it's own local ID for the endpoint
		addr, err := types.ParseCIDR(peerIP.String() + "/32")
		if err != nil {
			return err
		}

		ep := &endpoint{
			id:        eid,
			nid:       nid,
			addr:      addr,
			mac:       peerMac,
			profileId: hnsresponse.Id,
		}

		log.Infof("WINOVERLAY: peerAdd: creating endpoint object with HNS profileId %s", ep.profileId)

		n.addEndpoint(ep)
	}

	sbox := n.sandbox()
	if sbox == nil {
		return nil
	}

	IP := &net.IPNet{
		IP:   peerIP,
		Mask: peerIPMask,
	}

	s := n.getSubnetforIP(IP)
	if s == nil {
		return fmt.Errorf("couldn't find the subnet %q in network %q\n", IP.String(), n.id)
	}

	if err := n.obtainVxlanID(s); err != nil {
		return fmt.Errorf("couldn't get vxlan id for %q: %v", s.subnetIP.String(), err)
	}

	if err := n.joinSubnetSandbox(s, false); err != nil {
		return fmt.Errorf("subnet sandbox join failed for %q: %v", s.subnetIP.String(), err)
	}

	// Add neighbor entry for the peer IP
	if err := sbox.AddNeighbor(peerIP, peerMac, sbox.NeighborOptions().LinkName(s.vxlanName)); err != nil {
		return fmt.Errorf("could not add neigbor entry into the sandbox: %v", err)
	}

	return nil
}

func (d *driver) peerDelete(nid, eid string, peerIP net.IP, peerIPMask net.IPMask,
	peerMac net.HardwareAddr, vtep net.IP, updateDb bool) error {

	log.Infof("WINOVERLAY: Enter peerDelete for endpoint %s and peer ip %s", eid, peerIP.String())

	if err := validateID(nid, eid); err != nil {
		return err
	}

	n := d.network(nid)
	if n == nil {
		return nil
	}

	ep := n.endpoint(eid)
	if ep == nil {
		return fmt.Errorf("could not find endpoint with id %s", eid)
	}

	if updateDb {

		log.Infof("WINOVERLAY: peerDelete: telling HNS to delete REMOTE endpoint with profileId %v", ep.profileId)

		_, err := hcsshim.HNSEndpointRequest("DELETE", ep.profileId, "")
		if err != nil {
			return err
		}

		log.Infof("WINOVERLAY: PeerDelete: Updating DB for peerIP %s using PA %s", peerIP.String(), n.providerAddress)

		d.peerDbDelete(nid, eid, peerIP, peerIPMask, peerMac, net.ParseIP(n.providerAddress))

		n.deleteEndpoint(eid)
	}

	sbox := n.sandbox()
	if sbox == nil {
		return nil
	}

	// Delete neighbor entry for the peer IP
	if err := sbox.DeleteNeighbor(peerIP, peerMac, true); err != nil {
		return fmt.Errorf("could not delete neigbor entry into the sandbox: %v", err)
	}

	return nil
}
