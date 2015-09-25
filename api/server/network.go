package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/context"
	"github.com/docker/docker/pkg/parsers/filters"
	"github.com/docker/libnetwork"
	"github.com/docker/libnetwork/netlabel"
)

var (
	// ErrNoNetController represnts an error thrown when the controller is not initialized
	ErrNoNetController = errors.New("network controller is not initialized")
)

const (
	byID = iota
	byName
)

func (s *Server) getNetworksList(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := parseForm(r); err != nil {
		return err
	}

	filter := r.Form.Get("filters")
	netFilters, err := filters.FromParam(filter)
	if err != nil {
		return err
	}

	nc := s.daemon.NetworkController()
	if nc == nil {
		return ErrNoNetController
	}

	list := []*types.NetworkResource{}
	if names, ok := netFilters["name"]; ok {
		for _, name := range names {
			if nw, errRsp := findNetwork(nc, name, byName); errRsp == nil {
				list = append(list, buildNetworkResource(nw))
			}
		}
	} else if ids, ok := netFilters["id"]; ok {
		for _, id := range ids {
			// Return all the prefix-matching networks
			l := func(nw libnetwork.Network) bool {
				if strings.HasPrefix(nw.ID(), id) {
					list = append(list, buildNetworkResource(nw))
				}
				return false
			}
			nc.WalkNetworks(l)
		}
	} else {
		for _, nw := range nc.Networks() {
			list = append(list, buildNetworkResource(nw))
		}
	}
	return writeJSON(w, http.StatusOK, list)
}

func (s *Server) getNetwork(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := parseForm(r); err != nil {
		return err
	}

	nc := s.daemon.NetworkController()
	if nc == nil {
		return ErrNoNetController
	}

	nw, err := findNetwork(nc, vars["id"], byID)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, buildNetworkResource(nw))
}

func (s *Server) postNetworkCreate(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	var create types.NetworkCreate
	var warning string

	if err := parseForm(r); err != nil {
		return err
	}

	if err := checkForJSON(r); err != nil {
		return err
	}

	nc := s.daemon.NetworkController()
	if nc == nil {
		return ErrNoNetController
	}

	if err := json.NewDecoder(r.Body).Decode(&create); err != nil {
		return err
	}

	nw, err := findNetwork(nc, create.Name, byName)
	if _, ok := err.(libnetwork.ErrNoSuchNetwork); err != nil && !ok {
		return err
	}
	if nw != nil {
		if create.CheckDuplicate {
			return libnetwork.NetworkNameError(create.Name)
		}
		warning = fmt.Sprintf("Network with name %s (id : %s) already exists", nw.Name(), nw.ID())
	}

	processCreateDefaults(nc, &create)

	nw, err = nc.NewNetwork(create.Driver, create.Name, parseOptions(create.Options)...)
	if err != nil {
		return err
	}

	return writeJSON(w, http.StatusCreated, &types.NetworkCreateResponse{
		ID:      nw.ID(),
		Warning: warning,
	})
}

func (s *Server) postNetworkConnect(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	var connect types.NetworkConnect
	if err := parseForm(r); err != nil {
		return err
	}

	if err := checkForJSON(r); err != nil {
		return err
	}

	nc := s.daemon.NetworkController()
	if nc == nil {
		return ErrNoNetController
	}

	if err := json.NewDecoder(r.Body).Decode(&connect); err != nil {
		return err
	}

	nw, err := findNetwork(nc, vars["id"], byID)
	if err != nil {
		return err
	}

	container, err := s.daemon.Get(ctx, connect.Container)
	if err != nil {
		return fmt.Errorf("invalid container %s : %v", container, err)
	}
	return container.ConnectToNetwork(ctx, nw.Name())
}

func (s *Server) postNetworkDisconnect(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	var connect types.NetworkConnect
	if err := parseForm(r); err != nil {
		return err
	}

	if err := checkForJSON(r); err != nil {
		return err
	}

	nc := s.daemon.NetworkController()
	if nc == nil {
		return ErrNoNetController
	}

	if err := json.NewDecoder(r.Body).Decode(&connect); err != nil {
		return err
	}

	nw, err := findNetwork(nc, vars["id"], byID)
	if err != nil {
		return err
	}

	container, err := s.daemon.Get(ctx, connect.Container)
	if err != nil {
		return fmt.Errorf("invalid container %s : %v", container, err)
	}
	return container.DisconnectFromNetwork(nw)
}

func (s *Server) deleteNetwork(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := parseForm(r); err != nil {
		return err
	}

	nc := s.daemon.NetworkController()
	if nc == nil {
		return ErrNoNetController
	}

	nw, err := findNetwork(nc, vars["id"], byID)
	if err != nil {
		return err
	}

	return nw.Delete()
}

func findNetwork(c libnetwork.NetworkController, s string, by int) (libnetwork.Network, error) {
	switch by {
	case byID:
		return c.NetworkByID(s)
	case byName:
		if s == "" {
			s = c.Config().Daemon.DefaultNetwork
		}
		return c.NetworkByName(s)
	}
	return nil, errors.New("unexpected selector for network search")
}

func buildNetworkResource(nw libnetwork.Network) *types.NetworkResource {
	r := &types.NetworkResource{}
	if nw != nil {
		r.Name = nw.Name()
		r.ID = nw.ID()
		r.Driver = nw.Type()
		r.Containers = make(map[string]types.EndpointResource)
		epl := nw.Endpoints()
		for _, e := range epl {
			sb := e.Info().Sandbox()
			if sb == nil {
				continue
			}

			er := types.EndpointResource{}
			er.EndpointID = e.ID()
			if iface := e.Info().Iface(); iface != nil {
				if mac := iface.MacAddress(); mac != nil {
					er.MacAddress = mac.String()
				}
				if ip := iface.Address(); len(ip.IP) > 0 {
					er.IPv4Address = (&ip).String()
				}

				if ipv6 := iface.AddressIPv6(); len(ipv6.IP) > 0 {
					er.IPv6Address = (&ipv6).String()
				}
			}
			r.Containers[sb.ContainerID()] = er
		}
	}
	return r
}

func processCreateDefaults(c libnetwork.NetworkController, n *types.NetworkCreate) {
	if n.Driver == "" {
		n.Driver = c.Config().Daemon.DefaultDriver
	}

	if n.Options == nil {
		n.Options = make(map[string]interface{})
	}
	genericData, ok := n.Options[netlabel.GenericData]
	if !ok {
		genericData = make(map[string]interface{})
	}
	n.Options[netlabel.GenericData] = genericData
}

func parseOptions(options map[string]interface{}) []libnetwork.NetworkOption {
	var setFctList []libnetwork.NetworkOption

	if options != nil {
		setFctList = append(setFctList, libnetwork.NetworkOptionGeneric(options))
	}

	return setFctList
}
