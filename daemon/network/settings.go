package network

import "github.com/docker/docker/nat"

type Address struct {
	Addr      string
	PrefixLen int
}

type Settings struct {
	//sandboxInfo *sandbox.Info
	SandboxKey string
	NetworkID  string
	EndpointID string

	IPAddress              string
	IPPrefixLen            int
	SecondaryIPAddresses   []Address
	MacAddress             string
	LinkLocalIPv6Address   string
	LinkLocalIPv6PrefixLen int
	GlobalIPv6Address      string
	GlobalIPv6PrefixLen    int
	SecondaryIPv6Addresses []Address
	Gateway                string
	IPv6Gateway            string
	Bridge                 string
	PortMapping            map[string]map[string]string // Deprecated
	Ports                  nat.PortMap
}
