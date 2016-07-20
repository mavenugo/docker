package cluster

import (
	"errors"
	"fmt"
	"net"
)

func resolveListenAddr(specifiedAddr string) (string, string, error) {
	specifiedHost, specifiedPort, err := net.SplitHostPort(specifiedAddr)
	if err != nil {
		return "", "", fmt.Errorf("could not parse listen address %s", specifiedAddr)
	}

	// Does the host component match any of the interface names on the
	// system? If so, use the address from that interface.
	interfaceAddr, err := resolveInterfaceAddr(specifiedHost)
	if err == nil {
		return interfaceAddr.String(), specifiedPort, nil
	}
	if err != errNoSuchInterface {
		return "", "", err
	}

	return specifiedHost, specifiedPort, nil
}

func resolveAdvertiseAddr(advertiseAddr string, defaultAdvertiseAddr string, listenAddrPort string) (string, error) {
	// Approach:
	// - If an advertise address is specified, use that. Resolve the
	//   interface's address if an interface was specified in
	//   advertiseAddr. Fill in the port from listenAddrPort if necessary.
	// - If defaultAdvertiseAddr is not empty, use that with the port from
	//   listenAddrPort. Resolve the interface's address from
	//   if an interface name was specified in defaultAdvertiseAddr.
	// - Otherwise, try to autodetect the system's address. Use the port in
	//   listenAddrPort with this address if autodetection succeeds.

	if advertiseAddr != "" {
		advertiseHost, advertisePort, err := net.SplitHostPort(advertiseAddr)
		if err != nil {
			// Not a host:port specification
			advertiseHost = advertiseAddr
			advertisePort = listenAddrPort
		}

		// Does the host component match any of the interface names on the
		// system? If so, use the address from that interface.
		interfaceAddr, err := resolveInterfaceAddr(advertiseHost)
		if err == nil {
			return net.JoinHostPort(interfaceAddr.String(), advertisePort), nil
		}
		if err != errNoSuchInterface {
			return "", err
		}

		return net.JoinHostPort(advertiseHost, advertisePort), nil
	}

	if defaultAdvertiseAddr != "" {
		// Does the default advertise address component match any of the
		// interface names on the system? If so, use the address from
		// that interface.
		interfaceAddr, err := resolveInterfaceAddr(defaultAdvertiseAddr)
		if err == nil {
			return net.JoinHostPort(interfaceAddr.String(), listenAddrPort), nil
		}
		if err != errNoSuchInterface {
			return "", err
		}

		return net.JoinHostPort(defaultAdvertiseAddr, listenAddrPort), nil
	}

	systemAddr, err := resolveSystemAddr()
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(systemAddr.String(), listenAddrPort), nil
}

func resolveInterfaceAddr(specifiedInterface string) (net.IP, error) {
	// Use a specific interface's IP address.
	intf, err := net.InterfaceByName(specifiedInterface)
	if err != nil {
		return nil, errNoSuchInterface
	}

	addrs, err := intf.Addrs()
	if err != nil {
		return nil, err
	}

	var interfaceAddr4, interfaceAddr6 net.IP

	for _, addr := range addrs {
		ipAddr, ok := addr.(*net.IPNet)

		if ok {
			if ipAddr.IP.To4() != nil {
				// IPv4
				if interfaceAddr4 != nil {
					return nil, fmt.Errorf("interface %s has more than one IPv4 address", specifiedInterface)
				}
				interfaceAddr4 = ipAddr.IP
			} else {
				// IPv6
				if interfaceAddr6 != nil {
					return nil, fmt.Errorf("interface %s has more than one IPv6 address", specifiedInterface)
				}
				interfaceAddr6 = ipAddr.IP
			}
		}
	}

	if interfaceAddr4 == nil && interfaceAddr6 == nil {
		return nil, fmt.Errorf("interface %s has no usable IPv4 or IPv6 address", specifiedInterface)
	}

	// In the case that there's exactly one IPv4 address
	// and exactly one IPv6 address, favor IPv4 over IPv6.
	if interfaceAddr4 != nil {
		return interfaceAddr4, nil
	}
	return interfaceAddr6, nil
}

var errNoSuchInterface = errors.New("no such interface")
var errMultipleIPs = errors.New("could not choose an IP address to advertise since this system has multiple addresses")
var errNoIP = errors.New("could not find the system's IP address")

func resolveSystemAddr() (net.IP, error) {
	// Use the system's only IP address, or fail if there are
	// multiple addresses to choose from.
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var systemAddr net.IP

	for _, intf := range interfaces {
		// Skip inactive interfaces and loopback interfaces
		if (intf.Flags&net.FlagUp == 0) || (intf.Flags&net.FlagLoopback) != 0 {
			continue
		}

		addrs, err := intf.Addrs()
		if err != nil {
			continue
		}

		var interfaceAddr4, interfaceAddr6 net.IP

		for _, addr := range addrs {
			ipAddr, ok := addr.(*net.IPNet)

			// Skip loopback and link-local addresses
			if ok && ipAddr.IP.IsGlobalUnicast() {
				if ipAddr.IP.To4() != nil {
					// IPv4
					if interfaceAddr4 != nil {
						return nil, errMultipleIPs
					}
					interfaceAddr4 = ipAddr.IP
				} else {
					// IPv6
					if interfaceAddr6 != nil {
						return nil, errMultipleIPs
					}
					interfaceAddr6 = ipAddr.IP
				}
			}
		}

		// In the case that this interface has exactly one IPv4 address
		// and exactly one IPv6 address, favor IPv4 over IPv6.
		if interfaceAddr4 != nil {
			if systemAddr != nil {
				return nil, errMultipleIPs
			}
			systemAddr = interfaceAddr4
		} else if interfaceAddr6 != nil {
			if systemAddr != nil {
				return nil, errMultipleIPs
			}
			systemAddr = interfaceAddr6
		}
	}

	if systemAddr == nil {
		return nil, errNoIP
	}

	return systemAddr, nil
}
