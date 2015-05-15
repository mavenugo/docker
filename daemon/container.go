package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/docker/libcontainer/configs"
	"github.com/docker/libcontainer/devices"
	"github.com/docker/libcontainer/label"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/daemon/execdriver"
	"github.com/docker/docker/daemon/logger"
	"github.com/docker/docker/daemon/logger/jsonfilelog"
	"github.com/docker/docker/daemon/network"
	"github.com/docker/docker/image"
	"github.com/docker/docker/links"
	"github.com/docker/docker/nat"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/broadcastwriter"
	"github.com/docker/docker/pkg/directory"
	"github.com/docker/docker/pkg/ioutils"
	"github.com/docker/docker/pkg/jsonlog"
	"github.com/docker/docker/pkg/plugins"
	"github.com/docker/docker/pkg/promise"
	"github.com/docker/docker/pkg/stringid"
	"github.com/docker/docker/pkg/symlink"
	"github.com/docker/docker/pkg/ulimit"
	"github.com/docker/docker/runconfig"
	"github.com/docker/docker/utils"
	"github.com/docker/libnetwork"
	"github.com/docker/libnetwork/netutils"
	"github.com/docker/libnetwork/pkg/netlabel"
	"github.com/docker/libnetwork/pkg/options"
)

const DefaultPathEnv = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

var (
	ErrNotATTY               = errors.New("The PTY is not a file")
	ErrNoTTY                 = errors.New("No PTY found")
	ErrContainerStart        = errors.New("The container failed to start. Unknown error")
	ErrContainerStartTimeout = errors.New("The container failed to start due to timed out.")
)

type StreamConfig struct {
	stdout    *broadcastwriter.BroadcastWriter
	stderr    *broadcastwriter.BroadcastWriter
	stdin     io.ReadCloser
	stdinPipe io.WriteCloser
}

type Container struct {
	*State `json:"State"` // Needed for remote api version <= 1.11
	root   string         // Path to the "home" of the container, including metadata.
	basefs string         // Path to the graphdriver mountpoint

	ID string

	Created time.Time

	Path string
	Args []string

	Config  *runconfig.Config
	ImageID string `json:"Image"`

	NetworkSettings *network.Settings

	ResolvConfPath string
	HostnamePath   string
	HostsPath      string
	LogPath        string
	Name           string
	Driver         string
	ExecDriver     string

	command *execdriver.Command
	StreamConfig

	daemon                   *Daemon
	MountLabel, ProcessLabel string
	AppArmorProfile          string
	RestartCount             int
	UpdateDns                bool

	// Maps container paths to volume paths.  The key in this is the path to which
	// the volume is being mounted inside the container.  Value is the path of the
	// volume on disk
	Volumes map[string]string
	// Store rw/ro in a separate structure to preserve reverse-compatibility on-disk.
	// Easier than migrating older container configs :)
	VolumesRW  map[string]bool
	hostConfig *runconfig.HostConfig

	activeLinks  map[string]*links.Link
	monitor      *containerMonitor
	execCommands *execStore
	// logDriver for closing
	logDriver          logger.Logger
	logCopier          *logger.Copier
	AppliedVolumesFrom map[string]struct{}
}

func (container *Container) FromDisk() error {
	pth, err := container.jsonPath()
	if err != nil {
		return err
	}

	jsonSource, err := os.Open(pth)
	if err != nil {
		return err
	}
	defer jsonSource.Close()

	dec := json.NewDecoder(jsonSource)

	// Load container settings
	// udp broke compat of docker.PortMapping, but it's not used when loading a container, we can skip it
	if err := dec.Decode(container); err != nil && !strings.Contains(err.Error(), "docker.PortMapping") {
		return err
	}

	if err := label.ReserveLabel(container.ProcessLabel); err != nil {
		return err
	}
	return container.readHostConfig()
}

func (container *Container) toDisk() error {
	data, err := json.Marshal(container)
	if err != nil {
		return err
	}

	pth, err := container.jsonPath()
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(pth, data, 0666); err != nil {
		return err
	}

	return container.WriteHostConfig()
}

func (container *Container) ToDisk() error {
	container.Lock()
	err := container.toDisk()
	container.Unlock()
	return err
}

func (container *Container) readHostConfig() error {
	container.hostConfig = &runconfig.HostConfig{}
	// If the hostconfig file does not exist, do not read it.
	// (We still have to initialize container.hostConfig,
	// but that's OK, since we just did that above.)
	pth, err := container.hostConfigPath()
	if err != nil {
		return err
	}

	_, err = os.Stat(pth)
	if os.IsNotExist(err) {
		return nil
	}

	f, err := os.Open(pth)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewDecoder(f).Decode(&container.hostConfig)
}

func (container *Container) WriteHostConfig() error {
	data, err := json.Marshal(container.hostConfig)
	if err != nil {
		return err
	}

	pth, err := container.hostConfigPath()
	if err != nil {
		return err
	}

	return ioutil.WriteFile(pth, data, 0666)
}

func (container *Container) LogEvent(action string) {
	d := container.daemon
	d.EventsService.Log(
		action,
		container.ID,
		container.Config.Image,
	)
}

// Evaluates `path` in the scope of the container's basefs, with proper path
// sanitisation. Symlinks are all scoped to the basefs of the container, as
// though the container's basefs was `/`.
//
// The basefs of a container is the host-facing path which is bind-mounted as
// `/` inside the container. This method is essentially used to access a
// particular path inside the container as though you were a process in that
// container.
//
// NOTE: The returned path is *only* safely scoped inside the container's basefs
//       if no component of the returned path changes (such as a component
//       symlinking to a different path) between using this method and using the
//       path. See symlink.FollowSymlinkInScope for more details.
func (container *Container) GetResourcePath(path string) (string, error) {
	cleanPath := filepath.Join("/", path)
	return symlink.FollowSymlinkInScope(filepath.Join(container.basefs, cleanPath), container.basefs)
}

// Evaluates `path` in the scope of the container's root, with proper path
// sanitisation. Symlinks are all scoped to the root of the container, as
// though the container's root was `/`.
//
// The root of a container is the host-facing configuration metadata directory.
// Only use this method to safely access the container's `container.json` or
// other metadata files. If in doubt, use container.GetResourcePath.
//
// NOTE: The returned path is *only* safely scoped inside the container's root
//       if no component of the returned path changes (such as a component
//       symlinking to a different path) between using this method and using the
//       path. See symlink.FollowSymlinkInScope for more details.
func (container *Container) GetRootResourcePath(path string) (string, error) {
	cleanPath := filepath.Join("/", path)
	return symlink.FollowSymlinkInScope(filepath.Join(container.root, cleanPath), container.root)
}

func getDevicesFromPath(deviceMapping runconfig.DeviceMapping) (devs []*configs.Device, err error) {
	device, err := devices.DeviceFromPath(deviceMapping.PathOnHost, deviceMapping.CgroupPermissions)
	// if there was no error, return the device
	if err == nil {
		device.Path = deviceMapping.PathInContainer
		return append(devs, device), nil
	}

	// if the device is not a device node
	// try to see if it's a directory holding many devices
	if err == devices.ErrNotADevice {

		// check if it is a directory
		if src, e := os.Stat(deviceMapping.PathOnHost); e == nil && src.IsDir() {

			// mount the internal devices recursively
			filepath.Walk(deviceMapping.PathOnHost, func(dpath string, f os.FileInfo, e error) error {
				childDevice, e := devices.DeviceFromPath(dpath, deviceMapping.CgroupPermissions)
				if e != nil {
					// ignore the device
					return nil
				}

				// add the device to userSpecified devices
				childDevice.Path = strings.Replace(dpath, deviceMapping.PathOnHost, deviceMapping.PathInContainer, 1)
				devs = append(devs, childDevice)

				return nil
			})
		}
	}

	if len(devs) > 0 {
		return devs, nil
	}

	return devs, fmt.Errorf("error gathering device information while adding custom device %q: %s", deviceMapping.PathOnHost, err)
}

func populateCommand(c *Container, env []string) error {
	en := &execdriver.Network{
		NamespacePath: c.NetworkSettings.SandboxKey,
	}

	parts := strings.SplitN(string(c.hostConfig.NetworkMode), ":", 2)
	if parts[0] == "container" {
		nc, err := c.getNetworkedContainer()
		if err != nil {
			return err
		}
		en.ContainerID = nc.ID
	}

	ipc := &execdriver.Ipc{}

	if c.hostConfig.IpcMode.IsContainer() {
		ic, err := c.getIpcContainer()
		if err != nil {
			return err
		}
		ipc.ContainerID = ic.ID
	} else {
		ipc.HostIpc = c.hostConfig.IpcMode.IsHost()
	}

	pid := &execdriver.Pid{}
	pid.HostPid = c.hostConfig.PidMode.IsHost()

	uts := &execdriver.UTS{
		HostUTS: c.hostConfig.UTSMode.IsHost(),
	}

	// Build lists of devices allowed and created within the container.
	var userSpecifiedDevices []*configs.Device
	for _, deviceMapping := range c.hostConfig.Devices {
		devs, err := getDevicesFromPath(deviceMapping)
		if err != nil {
			return err
		}

		userSpecifiedDevices = append(userSpecifiedDevices, devs...)
	}
	allowedDevices := append(configs.DefaultAllowedDevices, userSpecifiedDevices...)

	autoCreatedDevices := append(configs.DefaultAutoCreatedDevices, userSpecifiedDevices...)

	// TODO: this can be removed after lxc-conf is fully deprecated
	lxcConfig, err := mergeLxcConfIntoOptions(c.hostConfig)
	if err != nil {
		return err
	}

	var rlimits []*ulimit.Rlimit
	ulimits := c.hostConfig.Ulimits

	// Merge ulimits with daemon defaults
	ulIdx := make(map[string]*ulimit.Ulimit)
	for _, ul := range ulimits {
		ulIdx[ul.Name] = ul
	}
	for name, ul := range c.daemon.config.Ulimits {
		if _, exists := ulIdx[name]; !exists {
			ulimits = append(ulimits, ul)
		}
	}

	for _, limit := range ulimits {
		rl, err := limit.GetRlimit()
		if err != nil {
			return err
		}
		rlimits = append(rlimits, rl)
	}

	resources := &execdriver.Resources{
		Memory:         c.hostConfig.Memory,
		MemorySwap:     c.hostConfig.MemorySwap,
		CpuShares:      c.hostConfig.CpuShares,
		CpusetCpus:     c.hostConfig.CpusetCpus,
		CpusetMems:     c.hostConfig.CpusetMems,
		CpuPeriod:      c.hostConfig.CpuPeriod,
		CpuQuota:       c.hostConfig.CpuQuota,
		BlkioWeight:    c.hostConfig.BlkioWeight,
		Rlimits:        rlimits,
		OomKillDisable: c.hostConfig.OomKillDisable,
	}

	processConfig := execdriver.ProcessConfig{
		Privileged: c.hostConfig.Privileged,
		Entrypoint: c.Path,
		Arguments:  c.Args,
		Tty:        c.Config.Tty,
		User:       c.Config.User,
	}

	processConfig.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	processConfig.Env = env

	c.command = &execdriver.Command{
		ID:                 c.ID,
		Rootfs:             c.RootfsPath(),
		ReadonlyRootfs:     c.hostConfig.ReadonlyRootfs,
		InitPath:           "/.dockerinit",
		WorkingDir:         c.Config.WorkingDir,
		Network:            en,
		Ipc:                ipc,
		Pid:                pid,
		UTS:                uts,
		Resources:          resources,
		AllowedDevices:     allowedDevices,
		AutoCreatedDevices: autoCreatedDevices,
		CapAdd:             c.hostConfig.CapAdd,
		CapDrop:            c.hostConfig.CapDrop,
		ProcessConfig:      processConfig,
		ProcessLabel:       c.GetProcessLabel(),
		MountLabel:         c.GetMountLabel(),
		LxcConfig:          lxcConfig,
		AppArmorProfile:    c.AppArmorProfile,
		CgroupParent:       c.hostConfig.CgroupParent,
	}

	return nil
}

func (container *Container) Start() (err error) {
	container.Lock()
	defer container.Unlock()

	if container.Running {
		return nil
	}

	if container.removalInProgress || container.Dead {
		return fmt.Errorf("Container is marked for removal and cannot be started.")
	}

	// if we encounter an error during start we need to ensure that any other
	// setup has been cleaned up properly
	defer func() {
		if err != nil {
			container.setError(err)
			// if no one else has set it, make sure we don't leave it at zero
			if container.ExitCode == 0 {
				container.ExitCode = 128
			}
			container.toDisk()
			container.cleanup()
		}
	}()

	if err := container.Mount(); err != nil {
		return err
	}
	if err := container.initializeNetworking(); err != nil {
		return err
	}
	container.verifyDaemonSettings()
	if err := container.prepareVolumes(); err != nil {
		return err
	}
	linkedEnv, err := container.setupLinkedContainers()
	if err != nil {
		return err
	}
	if err := container.setupWorkingDirectory(); err != nil {
		return err
	}
	env := container.createDaemonEnvironment(linkedEnv)
	if err := populateCommand(container, env); err != nil {
		return err
	}
	if err := container.setupMounts(); err != nil {
		return err
	}

	return container.waitForStart()
}

func (container *Container) Run() error {
	if err := container.Start(); err != nil {
		return err
	}
	container.WaitStop(-1 * time.Second)
	return nil
}

func (container *Container) Output() (output []byte, err error) {
	pipe := container.StdoutPipe()
	defer pipe.Close()
	if err := container.Start(); err != nil {
		return nil, err
	}
	output, err = ioutil.ReadAll(pipe)
	container.WaitStop(-1 * time.Second)
	return output, err
}

// StreamConfig.StdinPipe returns a WriteCloser which can be used to feed data
// to the standard input of the container's active process.
// Container.StdoutPipe and Container.StderrPipe each return a ReadCloser
// which can be used to retrieve the standard output (and error) generated
// by the container's active process. The output (and error) are actually
// copied and delivered to all StdoutPipe and StderrPipe consumers, using
// a kind of "broadcaster".

func (streamConfig *StreamConfig) StdinPipe() io.WriteCloser {
	return streamConfig.stdinPipe
}

func (streamConfig *StreamConfig) StdoutPipe() io.ReadCloser {
	reader, writer := io.Pipe()
	streamConfig.stdout.AddWriter(writer, "")
	return ioutils.NewBufReader(reader)
}

func (streamConfig *StreamConfig) StderrPipe() io.ReadCloser {
	reader, writer := io.Pipe()
	streamConfig.stderr.AddWriter(writer, "")
	return ioutils.NewBufReader(reader)
}

func (streamConfig *StreamConfig) StdoutLogPipe() io.ReadCloser {
	reader, writer := io.Pipe()
	streamConfig.stdout.AddWriter(writer, "stdout")
	return ioutils.NewBufReader(reader)
}

func (streamConfig *StreamConfig) StderrLogPipe() io.ReadCloser {
	reader, writer := io.Pipe()
	streamConfig.stderr.AddWriter(writer, "stderr")
	return ioutils.NewBufReader(reader)
}

func (container *Container) buildHostnameFile() error {
	hostnamePath, err := container.GetRootResourcePath("hostname")
	if err != nil {
		return err
	}
	container.HostnamePath = hostnamePath

	if container.Config.Domainname != "" {
		return ioutil.WriteFile(container.HostnamePath, []byte(fmt.Sprintf("%s.%s\n", container.Config.Hostname, container.Config.Domainname)), 0644)
	}
	return ioutil.WriteFile(container.HostnamePath, []byte(container.Config.Hostname+"\n"), 0644)
}

func (container *Container) buildJoinOptions() ([]libnetwork.EndpointOption, error) {
	var (
		joinOptions []libnetwork.EndpointOption
		err         error
		dns         []string
		dnsSearch   []string
	)

	joinOptions = append(joinOptions, libnetwork.JoinOptionHostname(container.Config.Hostname),
		libnetwork.JoinOptionDomainname(container.Config.Domainname))

	if container.hostConfig.NetworkMode.IsHost() {
		joinOptions = append(joinOptions, libnetwork.JoinOptionUseDefaultSandbox())
	}

	container.HostsPath, err = container.GetRootResourcePath("hosts")
	if err != nil {
		return nil, err
	}
	joinOptions = append(joinOptions, libnetwork.JoinOptionHostsPath(container.HostsPath))

	container.ResolvConfPath, err = container.GetRootResourcePath("resolv.conf")
	if err != nil {
		return nil, err
	}
	joinOptions = append(joinOptions, libnetwork.JoinOptionResolvConfPath(container.ResolvConfPath))

	if len(container.hostConfig.Dns) > 0 {
		dns = container.hostConfig.Dns
	} else if len(container.daemon.config.Dns) > 0 {
		dns = container.daemon.config.Dns
	}

	for _, d := range dns {
		joinOptions = append(joinOptions, libnetwork.JoinOptionDNS(d))
	}

	if len(container.hostConfig.DnsSearch) > 0 {
		dnsSearch = container.hostConfig.DnsSearch
	} else if len(container.daemon.config.DnsSearch) > 0 {
		dnsSearch = container.daemon.config.DnsSearch
	}

	for _, ds := range dnsSearch {
		joinOptions = append(joinOptions, libnetwork.JoinOptionDNSSearch(ds))
	}

	if container.NetworkSettings.SecondaryIPAddresses != nil {
		name := container.Config.Hostname
		if container.Config.Domainname != "" {
			name = name + "." + container.Config.Domainname
		}

		for _, a := range container.NetworkSettings.SecondaryIPAddresses {
			joinOptions = append(joinOptions, libnetwork.JoinOptionExtraHost(name, a.Addr))
		}
	}

	var childEndpoints, parentEndpoints []string

	children, err := container.daemon.Children(container.Name)
	if err != nil {
		return nil, err
	}

	for linkAlias, child := range children {
		_, alias := path.Split(linkAlias)
		// allow access to the linked container via the alias, real name, and container hostname
		aliasList := alias + " " + child.Config.Hostname
		// only add the name if alias isn't equal to the name
		if alias != child.Name[1:] {
			aliasList = aliasList + " " + child.Name[1:]
		}
		joinOptions = append(joinOptions, libnetwork.JoinOptionExtraHost(aliasList, child.NetworkSettings.IPAddress))
		if child.NetworkSettings.EndpointID != "" {
			childEndpoints = append(childEndpoints, child.NetworkSettings.EndpointID)
		}
	}

	for _, extraHost := range container.hostConfig.ExtraHosts {
		// allow IPv6 addresses in extra hosts; only split on first ":"
		parts := strings.SplitN(extraHost, ":", 2)
		joinOptions = append(joinOptions, libnetwork.JoinOptionExtraHost(parts[0], parts[1]))
	}

	refs := container.daemon.ContainerGraph().RefPaths(container.ID)
	for _, ref := range refs {
		if ref.ParentID == "0" {
			continue
		}

		c, err := container.daemon.Get(ref.ParentID)
		if err != nil {
			logrus.Error(err)
		}

		if c != nil && !container.daemon.config.DisableNetwork && container.hostConfig.NetworkMode.IsPrivate() {
			logrus.Debugf("Update /etc/hosts of %s for alias %s with ip %s", c.ID, ref.Name, container.NetworkSettings.IPAddress)
			joinOptions = append(joinOptions, libnetwork.JoinOptionParentUpdate(c.NetworkSettings.EndpointID, ref.Name, container.NetworkSettings.IPAddress))
			if c.NetworkSettings.EndpointID != "" {
				parentEndpoints = append(parentEndpoints, c.NetworkSettings.EndpointID)
			}
		}
	}

	linkOptions := options.Generic{
		netlabel.GenericData: options.Generic{
			"ParentEndpoints": parentEndpoints,
			"ChildEndpoints":  childEndpoints,
		},
	}

	joinOptions = append(joinOptions, libnetwork.JoinOptionGeneric(linkOptions))

	return joinOptions, nil
}

func (container *Container) buildPortMapInfo(n libnetwork.Network, ep libnetwork.Endpoint, networkSettings *network.Settings) (*network.Settings, error) {
	if ep == nil {
		return nil, fmt.Errorf("invalid endpoint while building port map info")
	}

	if networkSettings == nil {
		return nil, fmt.Errorf("invalid networksettings while building port map info")
	}

	epInfo, err := ep.Info()
	if err != nil {
		return nil, err
	}

	if epInfo == nil {
		// It is not an error for epInfo to be nil
		return networkSettings, nil
	}

	if mac, ok := epInfo[netlabel.MacAddress]; ok {
		networkSettings.MacAddress = mac.(net.HardwareAddr).String()
	}

	if mapData, ok := epInfo[netlabel.PortMap]; ok {
		if portMapping, ok := mapData.([]netutils.PortBinding); ok {
			networkSettings.Ports = nat.PortMap{}
			for _, pp := range portMapping {
				natPort := nat.NewPort(pp.Proto.String(), strconv.Itoa(int(pp.Port)))
				natBndg := nat.PortBinding{HostIp: pp.HostIP.String(), HostPort: strconv.Itoa(int(pp.HostPort))}
				if b, ok := networkSettings.Ports[natPort]; ok {
					networkSettings.Ports[natPort] = append(b, natBndg)
				} else {
					networkSettings.Ports[natPort] = []nat.PortBinding{natBndg}
				}
			}
		}
	}

	return networkSettings, nil
}

func (container *Container) buildSandBoxInfo(n libnetwork.Network, ep libnetwork.Endpoint, networkSettings *network.Settings) (*network.Settings, error) {
	if ep == nil {
		return nil, fmt.Errorf("invalid endpoint while building port map info")
	}

	if networkSettings == nil {
		return nil, fmt.Errorf("invalid networksettings while building port map info")
	}

	sinfo := ep.SandboxInfo()
	if sinfo == nil {
		// It is not an error to get an empty sandbox info
		return networkSettings, nil
	}

	networkSettings.Gateway = sinfo.Gateway.String()
	if sinfo.GatewayIPv6.To16() != nil {
		networkSettings.IPv6Gateway = sinfo.GatewayIPv6.String()
	}

	if len(sinfo.Interfaces) == 0 {
		return networkSettings, nil
	}

	i := sinfo.Interfaces[0]

	ones, _ := i.Address.Mask.Size()
	networkSettings.IPAddress = i.Address.IP.String()
	networkSettings.IPPrefixLen = ones

	if i.AddressIPv6 != nil {
		onesv6, _ := i.AddressIPv6.Mask.Size()
		networkSettings.GlobalIPv6Address = i.AddressIPv6.IP.String()
		networkSettings.GlobalIPv6PrefixLen = onesv6
	}

	if len(sinfo.Interfaces) == 1 {
		return networkSettings, nil
	}

	networkSettings.SecondaryIPAddresses = make([]network.Address, 0, len(sinfo.Interfaces)-1)
	networkSettings.SecondaryIPv6Addresses = make([]network.Address, 0, len(sinfo.Interfaces)-1)
	for _, i := range sinfo.Interfaces[1:] {
		ones, _ := i.Address.Mask.Size()
		addr := network.Address{Addr: i.Address.IP.String(), PrefixLen: ones}
		networkSettings.SecondaryIPAddresses = append(networkSettings.SecondaryIPAddresses, addr)

		if i.AddressIPv6 != nil {
			onesv6, _ := i.AddressIPv6.Mask.Size()
			addrv6 := network.Address{Addr: i.AddressIPv6.IP.String(), PrefixLen: onesv6}
			networkSettings.SecondaryIPv6Addresses = append(networkSettings.SecondaryIPv6Addresses, addrv6)
		}
	}

	return networkSettings, nil
}

func (container *Container) buildNetworkSettings(n libnetwork.Network, ep libnetwork.Endpoint) error {
	networkSettings := &network.Settings{NetworkID: n.ID(), EndpointID: ep.ID()}

	networkSettings, err := container.buildPortMapInfo(n, ep, networkSettings)
	if err != nil {
		return err
	}

	networkSettings, err = container.buildSandBoxInfo(n, ep, networkSettings)
	if err != nil {
		return err
	}

	if container.hostConfig.NetworkMode == runconfig.NetworkMode("bridge") {
		networkSettings.Bridge = container.daemon.config.Bridge.Iface
	}

	container.NetworkSettings = networkSettings
	return nil
}

func (container *Container) UpdateNetwork() error {
	n, err := container.daemon.netController.NetworkByID(container.NetworkSettings.NetworkID)
	if err != nil {
		return fmt.Errorf("error locating network id %s: %v", container.NetworkSettings.NetworkID, err)
	}
	if n == nil {
		return fmt.Errorf("no network found for network id %s", container.NetworkSettings.NetworkID)
	}

	ep, err := n.EndpointByID(container.NetworkSettings.EndpointID)
	if err != nil {
		return fmt.Errorf("error locating endpoint id %s: %v", container.NetworkSettings.EndpointID, err)
	}
	if ep == nil {
		return fmt.Errorf("no endpoint found for endpoint id %s", container.NetworkSettings.EndpointID)
	}

	err = ep.Leave(container.ID)
	if err != nil {
		return fmt.Errorf("endpoint leave failed: %v", err)

	}

	joinOptions, err := container.buildJoinOptions()
	if err != nil {
		return fmt.Errorf("Update networking failed: %v", err)
	}

	cData, err := ep.Join(container.ID, joinOptions...)
	if err != nil {
		return fmt.Errorf("endpoint join failed: %v", err)
	}

	container.NetworkSettings.SandboxKey = cData.SandboxKey

	return nil
}

func (container *Container) buildCreateEndpointOptions() ([]libnetwork.EndpointOption, error) {
	var (
		portSpecs     = make(nat.PortSet)
		bindings      = make(nat.PortMap)
		pbList        []netutils.PortBinding
		exposeList    []netutils.TransportPort
		createOptions []libnetwork.EndpointOption
	)

	if container.Config.PortSpecs != nil {
		if err := migratePortMappings(container.Config, container.hostConfig); err != nil {
			return nil, err
		}
		container.Config.PortSpecs = nil
		if err := container.WriteHostConfig(); err != nil {
			return nil, err
		}
	}

	if container.Config.ExposedPorts != nil {
		portSpecs = container.Config.ExposedPorts
	}

	if container.hostConfig.PortBindings != nil {
		for p, b := range container.hostConfig.PortBindings {
			bindings[p] = []nat.PortBinding{}
			for _, bb := range b {
				bindings[p] = append(bindings[p], nat.PortBinding{
					HostIp:   bb.HostIp,
					HostPort: bb.HostPort,
				})
			}
		}
	}

	container.NetworkSettings.PortMapping = nil

	ports := make([]nat.Port, len(portSpecs))
	var i int
	for p := range portSpecs {
		ports[i] = p
		i++
	}
	nat.SortPortMap(ports, bindings)
	for _, port := range ports {
		expose := netutils.TransportPort{}
		expose.Proto = netutils.ParseProtocol(port.Proto())
		expose.Port = uint16(port.Int())
		exposeList = append(exposeList, expose)

		pb := netutils.PortBinding{Port: expose.Port, Proto: expose.Proto}
		binding := bindings[port]
		for i := 0; i < len(binding); i++ {
			pbCopy := pb.GetCopy()
			pbCopy.HostPort = uint16(nat.Port(binding[i].HostPort).Int())
			pbCopy.HostIP = net.ParseIP(binding[i].HostIp)
			pbList = append(pbList, pbCopy)
		}

		if container.hostConfig.PublishAllPorts && len(binding) == 0 {
			pbList = append(pbList, pb)
		}
	}

	createOptions = append(createOptions,
		libnetwork.CreateOptionPortMapping(pbList),
		libnetwork.CreateOptionExposedPorts(exposeList))

	if container.Config.MacAddress != "" {
		mac, err := net.ParseMAC(container.Config.MacAddress)
		if err != nil {
			return nil, err
		}

		genericOption := options.Generic{
			netlabel.MacAddress: mac,
		}

		createOptions = append(createOptions, libnetwork.EndpointOptionGeneric(genericOption))
	}

	return createOptions, nil
}

func (container *Container) AllocateNetwork() error {
	mode := container.hostConfig.NetworkMode
	networkName := string(mode)
	if container.Config.NetworkDisabled || mode.IsContainer() {
		return nil
	}

	var err error

	parse := strings.Split(networkName, ":")
	driver := ""
	if len(parse) > 1 {
		_, err := plugins.Get(parse[0], "Network-Driver")
		if err != nil {
			logrus.Errorf("Error Loading Plugin for type : %s / network %s", parse[0], parse[1])
		}
		networkName = parse[1]
		driver = parse[0]
	}
	n, err := container.daemon.netController.NetworkByName(networkName)
	if err != nil {
		return fmt.Errorf("error locating network with name %s: %v", networkName, err)
	}
	if n == nil {
		n, err = container.daemon.netController.NewNetwork(driver, networkName)
		if err != nil {
			return fmt.Errorf("Failed to create network %s[%s] %v", networkName, driver, err)
		}
	}

	createOptions, err := container.buildCreateEndpointOptions()
	if err != nil {
		return err
	}

	ep, err := n.CreateEndpoint(container.Name, createOptions...)
	if err != nil {
		return err
	}

	err = container.buildNetworkSettings(n, ep)
	if err != nil {
		return err
	}

	joinOptions, err := container.buildJoinOptions()
	if err != nil {
		return err
	}

	cData, err := ep.Join(container.ID, joinOptions...)
	if err != nil {
		return err
	}

	container.NetworkSettings.SandboxKey = cData.SandboxKey
	container.WriteHostConfig()

	return nil
}

func (container *Container) ReleaseNetwork() {
	if container.hostConfig.NetworkMode.IsContainer() {
		return
	}

	n, err := container.daemon.netController.NetworkByID(container.NetworkSettings.NetworkID)
	if err != nil {
		logrus.Errorf("error locating network id %s: %v", container.NetworkSettings.NetworkID, err)
		return
	}
	if n == nil {
		logrus.Errorf("no network found for network id %s", container.NetworkSettings.NetworkID)
		return
	}

	ep, err := n.EndpointByID(container.NetworkSettings.EndpointID)
	if err != nil {
		logrus.Errorf("error locating endpoint id %s: %v", container.NetworkSettings.EndpointID, err)
		return
	}
	if ep == nil {
		logrus.Errorf("no endpoint found for endpoint id %s", container.NetworkSettings.EndpointID)
		return
	}

	err = ep.Leave(container.ID)
	if err != nil {
		logrus.Errorf("leaving endpoint failed: %v", err)
	}

	err = ep.Delete()
	if err != nil {
		logrus.Errorf("deleting endpoint failed: %v", err)
	}

	container.NetworkSettings = &network.Settings{}
}

// cleanup releases any network resources allocated to the container along with any rules
// around how containers are linked together.  It also unmounts the container's root filesystem.
func (container *Container) cleanup() {
	container.ReleaseNetwork()

	// Disable all active links
	if container.activeLinks != nil {
		for _, link := range container.activeLinks {
			link.Disable()
		}
	}

	if err := container.Unmount(); err != nil {
		logrus.Errorf("%v: Failed to umount filesystem: %v", container.ID, err)
	}

	for _, eConfig := range container.execCommands.s {
		container.daemon.unregisterExecCommand(eConfig)
	}
}

func (container *Container) KillSig(sig int) error {
	logrus.Debugf("Sending %d to %s", sig, container.ID)
	container.Lock()
	defer container.Unlock()

	// We could unpause the container for them rather than returning this error
	if container.Paused {
		return fmt.Errorf("Container %s is paused. Unpause the container before stopping", container.ID)
	}

	if !container.Running {
		return nil
	}

	// signal to the monitor that it should not restart the container
	// after we send the kill signal
	container.monitor.ExitOnNext()

	// if the container is currently restarting we do not need to send the signal
	// to the process.  Telling the monitor that it should exit on it's next event
	// loop is enough
	if container.Restarting {
		return nil
	}

	return container.daemon.Kill(container, sig)
}

// Wrapper aroung KillSig() suppressing "no such process" error.
func (container *Container) killPossiblyDeadProcess(sig int) error {
	err := container.KillSig(sig)
	if err == syscall.ESRCH {
		logrus.Debugf("Cannot kill process (pid=%d) with signal %d: no such process.", container.GetPid(), sig)
		return nil
	}
	return err
}

func (container *Container) Pause() error {
	container.Lock()
	defer container.Unlock()

	// We cannot Pause the container which is already paused
	if container.Paused {
		return fmt.Errorf("Container %s is already paused", container.ID)
	}

	// We cannot Pause the container which is not running
	if !container.Running {
		return fmt.Errorf("Container %s is not running", container.ID)
	}

	if err := container.daemon.execDriver.Pause(container.command); err != nil {
		return err
	}
	container.Paused = true
	return nil
}

func (container *Container) Unpause() error {
	container.Lock()
	defer container.Unlock()

	// We cannot unpause the container which is not paused
	if !container.Paused {
		return fmt.Errorf("Container %s is not paused, so what", container.ID)
	}

	// We cannot unpause the container which is not running
	if !container.Running {
		return fmt.Errorf("Container %s is not running", container.ID)
	}

	if err := container.daemon.execDriver.Unpause(container.command); err != nil {
		return err
	}
	container.Paused = false
	return nil
}

func (container *Container) Kill() error {
	if !container.IsRunning() {
		return nil
	}

	// 1. Send SIGKILL
	if err := container.killPossiblyDeadProcess(9); err != nil {
		return err
	}

	// 2. Wait for the process to die, in last resort, try to kill the process directly
	if _, err := container.WaitStop(10 * time.Second); err != nil {
		// Ensure that we don't kill ourselves
		if pid := container.GetPid(); pid != 0 {
			logrus.Infof("Container %s failed to exit within 10 seconds of kill - trying direct SIGKILL", stringid.TruncateID(container.ID))
			if err := syscall.Kill(pid, 9); err != nil {
				if err != syscall.ESRCH {
					return err
				}
				logrus.Debugf("Cannot kill process (pid=%d) with signal 9: no such process.", pid)
			}
		}
	}

	container.WaitStop(-1 * time.Second)
	return nil
}

func (container *Container) Stop(seconds int) error {
	if !container.IsRunning() {
		return nil
	}

	// 1. Send a SIGTERM
	if err := container.killPossiblyDeadProcess(15); err != nil {
		logrus.Infof("Failed to send SIGTERM to the process, force killing")
		if err := container.killPossiblyDeadProcess(9); err != nil {
			return err
		}
	}

	// 2. Wait for the process to exit on its own
	if _, err := container.WaitStop(time.Duration(seconds) * time.Second); err != nil {
		logrus.Infof("Container %v failed to exit within %d seconds of SIGTERM - using the force", container.ID, seconds)
		// 3. If it doesn't, then send SIGKILL
		if err := container.Kill(); err != nil {
			container.WaitStop(-1 * time.Second)
			return err
		}
	}
	return nil
}

func (container *Container) Restart(seconds int) error {
	// Avoid unnecessarily unmounting and then directly mounting
	// the container when the container stops and then starts
	// again
	if err := container.Mount(); err == nil {
		defer container.Unmount()
	}

	if err := container.Stop(seconds); err != nil {
		return err
	}
	return container.Start()
}

func (container *Container) Resize(h, w int) error {
	if !container.IsRunning() {
		return fmt.Errorf("Cannot resize container %s, container is not running", container.ID)
	}
	return container.command.ProcessConfig.Terminal.Resize(h, w)
}

func (container *Container) ExportRw() (archive.Archive, error) {
	if err := container.Mount(); err != nil {
		return nil, err
	}
	if container.daemon == nil {
		return nil, fmt.Errorf("Can't load storage driver for unregistered container %s", container.ID)
	}
	archive, err := container.daemon.Diff(container)
	if err != nil {
		container.Unmount()
		return nil, err
	}
	return ioutils.NewReadCloserWrapper(archive, func() error {
			err := archive.Close()
			container.Unmount()
			return err
		}),
		nil
}

func (container *Container) Export() (archive.Archive, error) {
	if err := container.Mount(); err != nil {
		return nil, err
	}

	archive, err := archive.Tar(container.basefs, archive.Uncompressed)
	if err != nil {
		container.Unmount()
		return nil, err
	}
	return ioutils.NewReadCloserWrapper(archive, func() error {
			err := archive.Close()
			container.Unmount()
			return err
		}),
		nil
}

func (container *Container) Mount() error {
	return container.daemon.Mount(container)
}

func (container *Container) changes() ([]archive.Change, error) {
	return container.daemon.Changes(container)
}

func (container *Container) Changes() ([]archive.Change, error) {
	container.Lock()
	defer container.Unlock()
	return container.changes()
}

func (container *Container) GetImage() (*image.Image, error) {
	if container.daemon == nil {
		return nil, fmt.Errorf("Can't get image of unregistered container")
	}
	return container.daemon.graph.Get(container.ImageID)
}

func (container *Container) Unmount() error {
	return container.daemon.Unmount(container)
}

func (container *Container) hostConfigPath() (string, error) {
	return container.GetRootResourcePath("hostconfig.json")
}

func (container *Container) jsonPath() (string, error) {
	return container.GetRootResourcePath("config.json")
}

// This method must be exported to be used from the lxc template
// This directory is only usable when the container is running
func (container *Container) RootfsPath() string {
	return container.basefs
}

func validateID(id string) error {
	if id == "" {
		return fmt.Errorf("Invalid empty id")
	}
	return nil
}

// GetSize, return real size, virtual size
func (container *Container) GetSize() (int64, int64) {
	var (
		sizeRw, sizeRootfs int64
		err                error
		driver             = container.daemon.driver
	)

	if err := container.Mount(); err != nil {
		logrus.Errorf("Failed to compute size of container rootfs %s: %s", container.ID, err)
		return sizeRw, sizeRootfs
	}
	defer container.Unmount()

	initID := fmt.Sprintf("%s-init", container.ID)
	sizeRw, err = driver.DiffSize(container.ID, initID)
	if err != nil {
		logrus.Errorf("Driver %s couldn't return diff size of container %s: %s", driver, container.ID, err)
		// FIXME: GetSize should return an error. Not changing it now in case
		// there is a side-effect.
		sizeRw = -1
	}

	if _, err = os.Stat(container.basefs); err != nil {
		if sizeRootfs, err = directory.Size(container.basefs); err != nil {
			sizeRootfs = -1
		}
	}
	return sizeRw, sizeRootfs
}

func (container *Container) Copy(resource string) (io.ReadCloser, error) {
	container.Lock()
	defer container.Unlock()
	var err error
	if err := container.Mount(); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			container.Unmount()
		}
	}()

	if err = container.mountVolumes(); err != nil {
		container.unmountVolumes()
		return nil, err
	}
	defer func() {
		if err != nil {
			container.unmountVolumes()
		}
	}()

	basePath, err := container.GetResourcePath(resource)
	if err != nil {
		return nil, err
	}

	stat, err := os.Stat(basePath)
	if err != nil {
		return nil, err
	}
	var filter []string
	if !stat.IsDir() {
		d, f := path.Split(basePath)
		basePath = d
		filter = []string{f}
	} else {
		filter = []string{path.Base(basePath)}
		basePath = path.Dir(basePath)
	}

	archive, err := archive.TarWithOptions(basePath, &archive.TarOptions{
		Compression:  archive.Uncompressed,
		IncludeFiles: filter,
	})
	if err != nil {
		return nil, err
	}

	return ioutils.NewReadCloserWrapper(archive, func() error {
			err := archive.Close()
			container.unmountVolumes()
			container.Unmount()
			return err
		}),
		nil
}

// Returns true if the container exposes a certain port
func (container *Container) Exposes(p nat.Port) bool {
	_, exists := container.Config.ExposedPorts[p]
	return exists
}

func (container *Container) HostConfig() *runconfig.HostConfig {
	return container.hostConfig
}

func (container *Container) SetHostConfig(hostConfig *runconfig.HostConfig) {
	container.hostConfig = hostConfig
}

func (container *Container) DisableLink(name string) {
	if container.activeLinks != nil {
		if link, exists := container.activeLinks[name]; exists {
			link.Disable()
			delete(container.activeLinks, name)
			if err := container.UpdateNetwork(); err != nil {
				logrus.Debugf("Could not update network to remove link: %v", err)
			}
		} else {
			logrus.Debugf("Could not find active link for %s", name)
		}
	}
}

func (container *Container) initializeNetworking() error {
	var err error

	// Make sure NetworkMode has an acceptable value before
	// initializing networking.
	if container.hostConfig.NetworkMode == runconfig.NetworkMode("") {
		container.hostConfig.NetworkMode = runconfig.NetworkMode("bridge")
	}

	if container.hostConfig.NetworkMode.IsContainer() {
		// we need to get the hosts files from the container to join
		nc, err := container.getNetworkedContainer()
		if err != nil {
			return err
		}
		container.HostnamePath = nc.HostnamePath
		container.HostsPath = nc.HostsPath
		container.ResolvConfPath = nc.ResolvConfPath
		container.Config.Hostname = nc.Config.Hostname
		container.Config.Domainname = nc.Config.Domainname
		return nil
	}

	if container.daemon.config.DisableNetwork {
		container.Config.NetworkDisabled = true
	}

	if container.hostConfig.NetworkMode.IsHost() {
		container.Config.Hostname, err = os.Hostname()
		if err != nil {
			return err
		}

		parts := strings.SplitN(container.Config.Hostname, ".", 2)
		if len(parts) > 1 {
			container.Config.Hostname = parts[0]
			container.Config.Domainname = parts[1]
		}

	}

	if err := container.AllocateNetwork(); err != nil {
		return err
	}

	return container.buildHostnameFile()
}

// Make sure the config is compatible with the current kernel
func (container *Container) verifyDaemonSettings() {
	if container.hostConfig.Memory > 0 && !container.daemon.sysInfo.MemoryLimit {
		logrus.Warnf("Your kernel does not support memory limit capabilities. Limitation discarded.")
		container.hostConfig.Memory = 0
	}
	if container.hostConfig.Memory > 0 && container.hostConfig.MemorySwap != -1 && !container.daemon.sysInfo.SwapLimit {
		logrus.Warnf("Your kernel does not support swap limit capabilities. Limitation discarded.")
		container.hostConfig.MemorySwap = -1
	}
	if container.daemon.sysInfo.IPv4ForwardingDisabled {
		logrus.Warnf("IPv4 forwarding is disabled. Networking will not work")
	}
}

func (container *Container) setupLinkedContainers() ([]string, error) {
	var (
		env    []string
		daemon = container.daemon
	)
	children, err := daemon.Children(container.Name)
	if err != nil {
		return nil, err
	}

	if len(children) > 0 {
		container.activeLinks = make(map[string]*links.Link, len(children))

		// If we encounter an error make sure that we rollback any network
		// config and iptables changes
		rollback := func() {
			for _, link := range container.activeLinks {
				link.Disable()
			}
			container.activeLinks = nil
		}

		for linkAlias, child := range children {
			if !child.IsRunning() {
				return nil, fmt.Errorf("Cannot link to a non running container: %s AS %s", child.Name, linkAlias)
			}

			link, err := links.NewLink(
				container.NetworkSettings.IPAddress,
				child.NetworkSettings.IPAddress,
				linkAlias,
				child.Config.Env,
				child.Config.ExposedPorts,
			)

			if err != nil {
				rollback()
				return nil, err
			}

			container.activeLinks[link.Alias()] = link
			if err := link.Enable(); err != nil {
				rollback()
				return nil, err
			}

			for _, envVar := range link.ToEnv() {
				env = append(env, envVar)
			}
		}
	}
	return env, nil
}

func (container *Container) createDaemonEnvironment(linkedEnv []string) []string {
	// if a domain name was specified, append it to the hostname (see #7851)
	fullHostname := container.Config.Hostname
	if container.Config.Domainname != "" {
		fullHostname = fmt.Sprintf("%s.%s", fullHostname, container.Config.Domainname)
	}
	// Setup environment
	env := []string{
		"PATH=" + DefaultPathEnv,
		"HOSTNAME=" + fullHostname,
		// Note: we don't set HOME here because it'll get autoset intelligently
		// based on the value of USER inside dockerinit, but only if it isn't
		// set already (ie, that can be overridden by setting HOME via -e or ENV
		// in a Dockerfile).
	}
	if container.Config.Tty {
		env = append(env, "TERM=xterm")
	}
	env = append(env, linkedEnv...)
	// because the env on the container can override certain default values
	// we need to replace the 'env' keys where they match and append anything
	// else.
	env = utils.ReplaceOrAppendEnvValues(env, container.Config.Env)

	return env
}

func (container *Container) setupWorkingDirectory() error {
	if container.Config.WorkingDir != "" {
		container.Config.WorkingDir = path.Clean(container.Config.WorkingDir)

		pth, err := container.GetResourcePath(container.Config.WorkingDir)
		if err != nil {
			return err
		}

		pthInfo, err := os.Stat(pth)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}

			if err := os.MkdirAll(pth, 0755); err != nil {
				return err
			}
		}
		if pthInfo != nil && !pthInfo.IsDir() {
			return fmt.Errorf("Cannot mkdir: %s is not a directory", container.Config.WorkingDir)
		}
	}
	return nil
}

func (container *Container) getLogConfig() runconfig.LogConfig {
	cfg := container.hostConfig.LogConfig
	if cfg.Type != "" { // container has log driver configured
		return cfg
	}
	// Use daemon's default log config for containers
	return container.daemon.defaultLogConfig
}

func (container *Container) getLogger() (logger.Logger, error) {
	cfg := container.getLogConfig()
	c, err := logger.GetLogDriver(cfg.Type)
	if err != nil {
		return nil, fmt.Errorf("Failed to get logging factory: %v", err)
	}
	ctx := logger.Context{
		ContainerID:   container.ID,
		ContainerName: container.Name,
	}

	// Set logging file for "json-logger"
	if cfg.Type == jsonfilelog.Name {
		ctx.LogPath, err = container.GetRootResourcePath(fmt.Sprintf("%s-json.log", container.ID))
		if err != nil {
			return nil, err
		}
	}
	return c(ctx)
}

func (container *Container) startLogging() error {
	cfg := container.getLogConfig()
	if cfg.Type == "none" {
		return nil // do not start logging routines
	}

	l, err := container.getLogger()
	if err != nil {
		return fmt.Errorf("Failed to initialize logging driver: %v", err)
	}

	copier, err := logger.NewCopier(container.ID, map[string]io.Reader{"stdout": container.StdoutPipe(), "stderr": container.StderrPipe()}, l)
	if err != nil {
		return err
	}
	container.logCopier = copier
	copier.Run()
	container.logDriver = l

	// set LogPath field only for json-file logdriver
	if jl, ok := l.(*jsonfilelog.JSONFileLogger); ok {
		container.LogPath = jl.LogPath()
	}

	return nil
}

func (container *Container) waitForStart() error {
	container.monitor = newContainerMonitor(container, container.hostConfig.RestartPolicy)

	// block until we either receive an error from the initial start of the container's
	// process or until the process is running in the container
	select {
	case <-container.monitor.startSignal:
	case err := <-promise.Go(container.monitor.Start):
		return err
	}

	return nil
}

func (container *Container) GetProcessLabel() string {
	// even if we have a process label return "" if we are running
	// in privileged mode
	if container.hostConfig.Privileged {
		return ""
	}
	return container.ProcessLabel
}

func (container *Container) GetMountLabel() string {
	if container.hostConfig.Privileged {
		return ""
	}
	return container.MountLabel
}

func (container *Container) getIpcContainer() (*Container, error) {
	containerID := container.hostConfig.IpcMode.Container()
	c, err := container.daemon.Get(containerID)
	if err != nil {
		return nil, err
	}
	if !c.IsRunning() {
		return nil, fmt.Errorf("cannot join IPC of a non running container: %s", containerID)
	}
	return c, nil
}

func (container *Container) getNetworkedContainer() (*Container, error) {
	parts := strings.SplitN(string(container.hostConfig.NetworkMode), ":", 2)
	switch parts[0] {
	case "container":
		if len(parts) != 2 {
			return nil, fmt.Errorf("no container specified to join network")
		}
		nc, err := container.daemon.Get(parts[1])
		if err != nil {
			return nil, err
		}
		if container == nc {
			return nil, fmt.Errorf("cannot join own network")
		}
		if !nc.IsRunning() {
			return nil, fmt.Errorf("cannot join network of a non running container: %s", parts[1])
		}
		return nc, nil
	default:
		return nil, fmt.Errorf("network mode not set to container")
	}
}

func (container *Container) Stats() (*execdriver.ResourceStats, error) {
	return container.daemon.Stats(container)
}

func (c *Container) LogDriverType() string {
	c.Lock()
	defer c.Unlock()
	if c.hostConfig.LogConfig.Type == "" {
		return c.daemon.defaultLogConfig.Type
	}
	return c.hostConfig.LogConfig.Type
}

func (container *Container) GetExecIDs() []string {
	return container.execCommands.List()
}

func (container *Container) Exec(execConfig *execConfig) error {
	container.Lock()
	defer container.Unlock()

	waitStart := make(chan struct{})

	callback := func(processConfig *execdriver.ProcessConfig, pid int) {
		if processConfig.Tty {
			// The callback is called after the process Start()
			// so we are in the parent process. In TTY mode, stdin/out/err is the PtySlave
			// which we close here.
			if c, ok := processConfig.Stdout.(io.Closer); ok {
				c.Close()
			}
		}
		close(waitStart)
	}

	// We use a callback here instead of a goroutine and an chan for
	// syncronization purposes
	cErr := promise.Go(func() error { return container.monitorExec(execConfig, callback) })

	// Exec should not return until the process is actually running
	select {
	case <-waitStart:
	case err := <-cErr:
		return err
	}

	return nil
}

func (container *Container) monitorExec(execConfig *execConfig, callback execdriver.StartCallback) error {
	var (
		err      error
		exitCode int
	)

	pipes := execdriver.NewPipes(execConfig.StreamConfig.stdin, execConfig.StreamConfig.stdout, execConfig.StreamConfig.stderr, execConfig.OpenStdin)
	exitCode, err = container.daemon.Exec(container, execConfig, pipes, callback)
	if err != nil {
		logrus.Errorf("Error running command in existing container %s: %s", container.ID, err)
	}

	logrus.Debugf("Exec task in container %s exited with code %d", container.ID, exitCode)
	if execConfig.OpenStdin {
		if err := execConfig.StreamConfig.stdin.Close(); err != nil {
			logrus.Errorf("Error closing stdin while running in %s: %s", container.ID, err)
		}
	}
	if err := execConfig.StreamConfig.stdout.Clean(); err != nil {
		logrus.Errorf("Error closing stdout while running in %s: %s", container.ID, err)
	}
	if err := execConfig.StreamConfig.stderr.Clean(); err != nil {
		logrus.Errorf("Error closing stderr while running in %s: %s", container.ID, err)
	}
	if execConfig.ProcessConfig.Terminal != nil {
		if err := execConfig.ProcessConfig.Terminal.Close(); err != nil {
			logrus.Errorf("Error closing terminal while running in container %s: %s", container.ID, err)
		}
	}

	return err
}

func (c *Container) Attach(stdin io.ReadCloser, stdout io.Writer, stderr io.Writer) chan error {
	return attach(&c.StreamConfig, c.Config.OpenStdin, c.Config.StdinOnce, c.Config.Tty, stdin, stdout, stderr)
}

func (c *Container) AttachWithLogs(stdin io.ReadCloser, stdout, stderr io.Writer, logs, stream bool) error {
	if logs {
		logDriver, err := c.getLogger()
		cLog, err := logDriver.GetReader()

		if err != nil {
			logrus.Errorf("Error reading logs: %s", err)
		} else if c.LogDriverType() != jsonfilelog.Name {
			logrus.Errorf("Reading logs not implemented for driver %s", c.LogDriverType())
		} else {
			dec := json.NewDecoder(cLog)
			for {
				l := &jsonlog.JSONLog{}

				if err := dec.Decode(l); err == io.EOF {
					break
				} else if err != nil {
					logrus.Errorf("Error streaming logs: %s", err)
					break
				}
				if l.Stream == "stdout" && stdout != nil {
					io.WriteString(stdout, l.Log)
				}
				if l.Stream == "stderr" && stderr != nil {
					io.WriteString(stderr, l.Log)
				}
			}
		}
	}

	//stream
	if stream {
		var stdinPipe io.ReadCloser
		if stdin != nil {
			r, w := io.Pipe()
			go func() {
				defer w.Close()
				defer logrus.Debugf("Closing buffered stdin pipe")
				io.Copy(w, stdin)
			}()
			stdinPipe = r
		}
		<-c.Attach(stdinPipe, stdout, stderr)
		// If we are in stdinonce mode, wait for the process to end
		// otherwise, simply return
		if c.Config.StdinOnce && !c.Config.Tty {
			c.WaitStop(-1 * time.Second)
		}
	}
	return nil
}

func attach(streamConfig *StreamConfig, openStdin, stdinOnce, tty bool, stdin io.ReadCloser, stdout io.Writer, stderr io.Writer) chan error {
	var (
		cStdout, cStderr io.ReadCloser
		cStdin           io.WriteCloser
		wg               sync.WaitGroup
		errors           = make(chan error, 3)
	)

	if stdin != nil && openStdin {
		cStdin = streamConfig.StdinPipe()
		wg.Add(1)
	}

	if stdout != nil {
		cStdout = streamConfig.StdoutPipe()
		wg.Add(1)
	}

	if stderr != nil {
		cStderr = streamConfig.StderrPipe()
		wg.Add(1)
	}

	// Connect stdin of container to the http conn.
	go func() {
		if stdin == nil || !openStdin {
			return
		}
		logrus.Debugf("attach: stdin: begin")
		defer func() {
			if stdinOnce && !tty {
				cStdin.Close()
			} else {
				// No matter what, when stdin is closed (io.Copy unblock), close stdout and stderr
				if cStdout != nil {
					cStdout.Close()
				}
				if cStderr != nil {
					cStderr.Close()
				}
			}
			wg.Done()
			logrus.Debugf("attach: stdin: end")
		}()

		var err error
		if tty {
			_, err = copyEscapable(cStdin, stdin)
		} else {
			_, err = io.Copy(cStdin, stdin)

		}
		if err == io.ErrClosedPipe {
			err = nil
		}
		if err != nil {
			logrus.Errorf("attach: stdin: %s", err)
			errors <- err
			return
		}
	}()

	attachStream := func(name string, stream io.Writer, streamPipe io.ReadCloser) {
		if stream == nil {
			return
		}
		defer func() {
			// Make sure stdin gets closed
			if stdin != nil {
				stdin.Close()
			}
			streamPipe.Close()
			wg.Done()
			logrus.Debugf("attach: %s: end", name)
		}()

		logrus.Debugf("attach: %s: begin", name)
		_, err := io.Copy(stream, streamPipe)
		if err == io.ErrClosedPipe {
			err = nil
		}
		if err != nil {
			logrus.Errorf("attach: %s: %v", name, err)
			errors <- err
		}
	}

	go attachStream("stdout", stdout, cStdout)
	go attachStream("stderr", stderr, cStderr)

	return promise.Go(func() error {
		wg.Wait()
		close(errors)
		for err := range errors {
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// Code c/c from io.Copy() modified to handle escape sequence
func copyEscapable(dst io.Writer, src io.ReadCloser) (written int64, err error) {
	buf := make([]byte, 32*1024)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			// ---- Docker addition
			// char 16 is C-p
			if nr == 1 && buf[0] == 16 {
				nr, er = src.Read(buf)
				// char 17 is C-q
				if nr == 1 && buf[0] == 17 {
					if err := src.Close(); err != nil {
						return 0, err
					}
					return 0, nil
				}
			}
			// ---- End of docker
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			err = er
			break
		}
	}
	return written, err
}
