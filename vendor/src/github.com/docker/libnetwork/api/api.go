package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/docker/libnetwork"
	"github.com/docker/libnetwork/netutils"
	"github.com/docker/libnetwork/sandbox"
	"github.com/gorilla/mux"
)

var (
	successResponse  = responseStatus{Status: "Success", StatusCode: http.StatusOK}
	createdResponse  = responseStatus{Status: "Created", StatusCode: http.StatusCreated}
	mismatchResponse = responseStatus{Status: "Body/URI parameter mismatch", StatusCode: http.StatusBadRequest}
)

const (
	urlNwName = "name"
	urlNwID   = "id"
	urlEpName = "endpoint-name"
	urlEpID   = "endpoint-id"
	urlCnID   = "container-id"
)

// NewHTTPHandler creates and initialize the HTTP handler to serve the requests for libnetwork
func NewHTTPHandler(c libnetwork.NetworkController) func(w http.ResponseWriter, req *http.Request) {
	h := &httpHandler{c: c}
	h.initRouter()
	return h.handleRequest
}

type responseStatus struct {
	Status     string
	StatusCode int
}

func (r *responseStatus) isOK() bool {
	return r.StatusCode == http.StatusOK || r.StatusCode == http.StatusCreated
}

type processor func(c libnetwork.NetworkController, vars map[string]string, body []byte) (interface{}, *responseStatus)

type httpHandler struct {
	c libnetwork.NetworkController
	r *mux.Router
}

func (h *httpHandler) handleRequest(w http.ResponseWriter, req *http.Request) {
	// Make sure the service is there
	if h.c == nil {
		http.Error(w, "NetworkController is not available", http.StatusServiceUnavailable)
		return
	}

	// Get handler from router and execute it
	h.r.ServeHTTP(w, req)
}

func (h *httpHandler) initRouter() {
	m := map[string]map[string]processor{
		"GET": {
			"/networks":                                                                   procGetNetworks,
			"/networks/name/{" + urlNwName + ":.*}":                                       procGetNetwork,
			"/networks/id/{" + urlNwID + ":.*}":                                           procGetNetwork,
			"/networks/name/{" + urlNwName + ":.*}/endpoints/":                            procGetEndpoints,
			"/networks/id/{" + urlNwID + ":.*}/endpoints/":                                procGetEndpoints,
			"/networks/name/{" + urlNwName + ":.*}/endpoints/name/{" + urlEpName + ":.*}": procGetEndpoint,
			"/networks/id/{" + urlNwName + ":.*}/endpoints/name/{" + urlEpName + ":.*}":   procGetEndpoint,
			"/networks/name/{" + urlNwName + ":.*}/endpoints/id/{" + urlEpID + ":.*}":     procGetEndpoint,
			"/networks/id/{" + urlNwID + ":.*}/endpoints/id/{" + urlEpID + ":.*}":         procGetEndpoint,
		},
		"POST": {
			"/networks/name/{" + urlNwName + ":.*}":                                                                     procCreateNetwork,
			"/networks/name/{" + urlNwName + ":.*}/endpoint/name/{" + urlEpName + ":.*}":                                procCreateEndpoint,
			"/networks/name/{" + urlNwName + ":.*}/endpoint/name/{" + urlEpName + ":.*}/container/{" + urlCnID + ":.*}": procJoinEndpoint,
		},
		"DELETE": {
			"/networks/name/{" + urlNwName + ":.*}":                                                                     procDeleteNetwork,
			"/networks/id/{" + urlNwID + ":.*}":                                                                         procDeleteNetwork,
			"/networks/name/{" + urlNwName + ":.*}/endpoints/name/{" + urlEpName + ":.*}":                               procDeleteEndpoint,
			"/networks/name/{" + urlNwName + ":.*}/endpoints/id/{" + urlEpID + ":.*}":                                   procDeleteEndpoint,
			"/networks/id/{" + urlNwID + ":.*}/endpoints/name/{" + urlEpName + ":.*}":                                   procDeleteEndpoint,
			"/networks/id/{" + urlNwID + ":.*}/endpoints/id/{" + urlEpID + ":.*}":                                       procDeleteEndpoint,
			"/networks/name/{" + urlNwName + ":.*}/endpoint/name/{" + urlEpName + ":.*}/container/{" + urlCnID + ":.*}": procLeaveEndpoint,
			"/networks/name/{" + urlNwName + ":.*}/endpoint/id/{" + urlEpID + ":.*}/container/{" + urlCnID + ":.*}":     procLeaveEndpoint,
			"/networks/id/{" + urlNwID + ":.*}/endpoint/name/{" + urlEpName + ":.*}/container/{" + urlCnID + ":.*}":     procLeaveEndpoint,
			"/networks/id/{" + urlNwID + ":.*}/endpoint/id/{" + urlEpID + ":.*}/container/{" + urlCnID + ":.*}":         procLeaveEndpoint,
		},
	}

	h.r = mux.NewRouter()
	for method, routes := range m {
		for route, fct := range routes {
			f := makeHandler(h.c, fct)
			h.r.Path(route).Methods(method).HandlerFunc(f)
		}
	}
}

func makeHandler(ctrl libnetwork.NetworkController, fct processor) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		var (
			body []byte
			err  error
		)
		if req.Body != nil {
			body, err = ioutil.ReadAll(req.Body)
			if err != nil {
				http.Error(w, "Invalid body: "+err.Error(), http.StatusBadRequest)
				return
			}
		}

		res, rsp := fct(ctrl, mux.Vars(req), body)
		if !rsp.isOK() {
			http.Error(w, rsp.Status, rsp.StatusCode)
			return
		}
		if res != nil {
			writeJSON(w, rsp.StatusCode, res)
		}
	}
}

/***********
 Resources
************/

// networkResource is the body of the "get network" http response message
type networkResource struct {
	Name      string
	ID        string
	Type      string
	Endpoints []*endpointResource
}

// endpointResource is the body of the "get endpoint" http response message
type endpointResource struct {
	Name    string
	ID      string
	Network string
	Info    sandbox.Info
}

func buildNetworkResource(nw libnetwork.Network) *networkResource {
	r := &networkResource{}
	if nw != nil {
		r.Name = nw.Name()
		r.ID = nw.ID()
		r.Type = nw.Type()
		epl := nw.Endpoints()
		r.Endpoints = make([]*endpointResource, 0, len(epl))
		for _, e := range epl {
			epr := buildEndpointResource(e)
			r.Endpoints = append(r.Endpoints, epr)
		}
	}
	return r
}

func buildEndpointResource(ep libnetwork.Endpoint) *endpointResource {
	r := &endpointResource{}
	if ep != nil {
		r.Name = ep.Name()
		r.ID = ep.ID()
		r.Network = ep.Network()

		i := ep.SandboxInfo()
		if i != nil {
			r.Info = *i
		}
	}
	return r
}

/***********
 Body types
************/

// networkCreate is the expected body of the "create network" http request message
type networkCreate struct {
	Name        string
	NetworkType string
	Options     map[string]interface{}
}

// endpointCreate represents the body of the "create endpoint" http request message
type endpointCreate struct {
	Name         string
	NetworkID    string
	ExposedPorts []netutils.TransportPort
	PortMapping  []netutils.PortBinding
}

// endpointJoin represents the expected body of the "join endpoint" or "leave endpoint" http request messages
type endpointJoin struct {
	ContainerID       string
	HostName          string
	DomainName        string
	HostsPath         string
	ResolvConfPath    string
	DNS               []string
	ExtraHosts        []endpointExtraHost
	ParentUpdates     []endpointParentUpdate
	UseDefaultSandbox bool
}

// EndpointExtraHost represents the extra host object
type endpointExtraHost struct {
	Name    string
	Address string
}

// EndpointParentUpdate is the object carrying the information about the
// endpoint parent that needs to be updated
type endpointParentUpdate struct {
	EndpointID string
	Name       string
	Address    string
}

func (ej *endpointJoin) parseOptions() []libnetwork.EndpointOption {
	var setFctList []libnetwork.EndpointOption
	if ej.HostName != "" {
		setFctList = append(setFctList, libnetwork.JoinOptionHostname(ej.HostName))
	}
	if ej.DomainName != "" {
		setFctList = append(setFctList, libnetwork.JoinOptionDomainname(ej.DomainName))
	}
	if ej.HostsPath != "" {
		setFctList = append(setFctList, libnetwork.JoinOptionHostsPath(ej.HostsPath))
	}
	if ej.ResolvConfPath != "" {
		setFctList = append(setFctList, libnetwork.JoinOptionResolvConfPath(ej.ResolvConfPath))
	}
	if ej.UseDefaultSandbox {
		setFctList = append(setFctList, libnetwork.JoinOptionUseDefaultSandbox())
	}
	if ej.DNS != nil {
		for _, d := range ej.DNS {
			setFctList = append(setFctList, libnetwork.JoinOptionDNS(d))
		}
	}
	if ej.ExtraHosts != nil {
		for _, e := range ej.ExtraHosts {
			setFctList = append(setFctList, libnetwork.JoinOptionExtraHost(e.Name, e.Address))
		}
	}
	if ej.ParentUpdates != nil {
		for _, p := range ej.ParentUpdates {
			setFctList = append(setFctList, libnetwork.JoinOptionParentUpdate(p.EndpointID, p.Name, p.Address))
		}
	}
	return setFctList
}

/******************
 Process functions
*******************/

/***************************
 NetworkController interface
****************************/
func procCreateNetwork(c libnetwork.NetworkController, vars map[string]string, body []byte) (interface{}, *responseStatus) {
	var create networkCreate

	err := json.Unmarshal(body, &create)
	if err != nil {
		return "", &responseStatus{Status: "Invalid body: " + err.Error(), StatusCode: http.StatusBadRequest}
	}

	name := vars[urlNwName]
	if name != create.Name {
		return "", &mismatchResponse
	}

	nw, err := c.NewNetwork(create.NetworkType, name, nil)
	if err != nil {
		return "", convertNetworkError(err)
	}

	return nw.ID(), &createdResponse
}

func procGetNetwork(c libnetwork.NetworkController, vars map[string]string, body []byte) (interface{}, *responseStatus) {
	t, by := detectNetworkTarget(vars)
	nw, errRsp := findNetwork(c, t, by)
	if !errRsp.isOK() {
		return nil, errRsp
	}
	return buildNetworkResource(nw), &successResponse
}

func procGetNetworks(c libnetwork.NetworkController, vars map[string]string, body []byte) (interface{}, *responseStatus) {
	var list []*networkResource
	for _, nw := range c.Networks() {
		nwr := buildNetworkResource(nw)
		list = append(list, nwr)
	}
	return list, &successResponse
}

/******************
 Network interface
*******************/
func procCreateEndpoint(c libnetwork.NetworkController, vars map[string]string, body []byte) (interface{}, *responseStatus) {
	var ec endpointCreate

	err := json.Unmarshal(body, &ec)
	if err != nil {
		return "", &responseStatus{Status: "Invalid body: " + err.Error(), StatusCode: http.StatusBadRequest}
	}

	epn := vars[urlEpName]
	if ec.Name != epn {
		return "", &mismatchResponse
	}

	nwT, nwBy := detectNetworkTarget(vars)
	n, errRsp := findNetwork(c, nwT, nwBy)
	if !errRsp.isOK() {
		return "", errRsp
	}

	if ec.NetworkID != n.ID() {
		return "", &mismatchResponse
	}

	var setFctList []libnetwork.EndpointOption
	if ec.ExposedPorts != nil {
		setFctList = append(setFctList, libnetwork.CreateOptionExposedPorts(ec.ExposedPorts))
	}
	if ec.PortMapping != nil {
		setFctList = append(setFctList, libnetwork.CreateOptionPortMapping(ec.PortMapping))
	}

	ep, err := n.CreateEndpoint(epn, setFctList...)
	if err != nil {
		return "", convertNetworkError(err)
	}

	return ep.ID(), &createdResponse
}

func procGetEndpoint(c libnetwork.NetworkController, vars map[string]string, body []byte) (interface{}, *responseStatus) {
	nwT, nwBy := detectNetworkTarget(vars)
	epT, epBy := detectEndpointTarget(vars)

	ep, errRsp := findEndpoint(c, nwT, epT, nwBy, epBy)
	if !errRsp.isOK() {
		return nil, errRsp
	}

	return buildEndpointResource(ep), &successResponse
}

func procGetEndpoints(c libnetwork.NetworkController, vars map[string]string, body []byte) (interface{}, *responseStatus) {
	target, by := detectNetworkTarget(vars)

	nw, errRsp := findNetwork(c, target, by)
	if !errRsp.isOK() {
		return nil, errRsp
	}

	var list []*endpointResource
	for _, ep := range nw.Endpoints() {
		epr := buildEndpointResource(ep)
		list = append(list, epr)
	}

	return list, &successResponse
}

func procDeleteNetwork(c libnetwork.NetworkController, vars map[string]string, body []byte) (interface{}, *responseStatus) {
	target, by := detectNetworkTarget(vars)

	nw, errRsp := findNetwork(c, target, by)
	if !errRsp.isOK() {
		return nil, errRsp
	}

	err := nw.Delete()
	if err != nil {
		return nil, convertNetworkError(err)
	}

	return nil, &successResponse
}

/******************
 Endpoint interface
*******************/
func procJoinEndpoint(c libnetwork.NetworkController, vars map[string]string, body []byte) (interface{}, *responseStatus) {
	var ej endpointJoin
	err := json.Unmarshal(body, &ej)
	if err != nil {
		return nil, &responseStatus{Status: "Invalid body: " + err.Error(), StatusCode: http.StatusBadRequest}
	}

	cid := vars[urlCnID]
	if ej.ContainerID != cid {
		return "", &mismatchResponse
	}

	nwT, nwBy := detectNetworkTarget(vars)
	epT, epBy := detectEndpointTarget(vars)

	ep, errRsp := findEndpoint(c, nwT, epT, nwBy, epBy)
	if !errRsp.isOK() {
		return nil, errRsp
	}

	cd, err := ep.Join(ej.ContainerID, ej.parseOptions()...)
	if err != nil {
		return nil, convertNetworkError(err)
	}
	return cd, &successResponse
}

func procLeaveEndpoint(c libnetwork.NetworkController, vars map[string]string, body []byte) (interface{}, *responseStatus) {
	nwT, nwBy := detectNetworkTarget(vars)
	epT, epBy := detectEndpointTarget(vars)

	ep, errRsp := findEndpoint(c, nwT, epT, nwBy, epBy)
	if !errRsp.isOK() {
		return nil, errRsp
	}

	err := ep.Leave(vars[urlCnID], nil)
	if err != nil {
		return nil, convertNetworkError(err)
	}

	return nil, &successResponse
}

func procDeleteEndpoint(c libnetwork.NetworkController, vars map[string]string, body []byte) (interface{}, *responseStatus) {
	nwT, nwBy := detectNetworkTarget(vars)
	epT, epBy := detectEndpointTarget(vars)

	ep, errRsp := findEndpoint(c, nwT, epT, nwBy, epBy)
	if !errRsp.isOK() {
		return nil, errRsp
	}

	err := ep.Delete()
	if err != nil {
		return nil, convertNetworkError(err)
	}

	return nil, &successResponse
}

/***********
  Utilities
************/
const (
	byID = iota
	byName
)

func detectNetworkTarget(vars map[string]string) (string, int) {
	if target, ok := vars[urlNwName]; ok {
		return target, byName
	}
	if target, ok := vars[urlNwID]; ok {
		return target, byID
	}
	// vars are populated from the URL, following cannot happen
	panic("Missing URL variable parameter for network")
}

func detectEndpointTarget(vars map[string]string) (string, int) {
	if target, ok := vars[urlEpName]; ok {
		return target, byName
	}
	if target, ok := vars[urlEpID]; ok {
		return target, byID
	}
	// vars are populated from the URL, following cannot happen
	panic("Missing URL variable parameter for endpoint")
}

func findNetwork(c libnetwork.NetworkController, s string, by int) (libnetwork.Network, *responseStatus) {
	var (
		nw  libnetwork.Network
		err error
	)
	switch by {
	case byID:
		nw, err = c.NetworkByID(s)
	case byName:
		nw, err = c.NetworkByName(s)
	default:
		panic(fmt.Sprintf("unexpected selector for network search: %d", by))
	}
	if err != nil {
		return nil, &responseStatus{Status: err.Error(), StatusCode: http.StatusBadRequest}
	}
	if nw == nil {
		return nil, &responseStatus{Status: "Resource not found: Network", StatusCode: http.StatusNotFound}
	}
	return nw, &successResponse
}

func findEndpoint(c libnetwork.NetworkController, ns, es string, nwBy, epBy int) (libnetwork.Endpoint, *responseStatus) {
	nw, errRsp := findNetwork(c, ns, nwBy)
	if !errRsp.isOK() {
		return nil, errRsp
	}
	var (
		err error
		ep  libnetwork.Endpoint
	)
	switch epBy {
	case byID:
		ep, err = nw.EndpointByID(es)
	case byName:
		ep, err = nw.EndpointByName(es)
	default:
		panic(fmt.Sprintf("unexpected selector for endpoint search: %d", epBy))
	}
	if err != nil {
		return nil, &responseStatus{Status: err.Error(), StatusCode: http.StatusBadRequest}
	}
	if ep == nil {
		return nil, &responseStatus{Status: "Resource not found: Endpoint", StatusCode: http.StatusNotFound}
	}
	return ep, &successResponse
}

func convertNetworkError(err error) *responseStatus {
	// No real libnetwork error => http error code conversion for now.
	// Will came in later when new interface for libnetwork error is vailable
	return &responseStatus{Status: err.Error(), StatusCode: http.StatusBadRequest}
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	return json.NewEncoder(w).Encode(v)
}
