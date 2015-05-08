package plugins

import plug "github.com/docker/docker/pkg/plugins"

// currently created by hand. generation tool would generate this like:
// $ rpc-gen volume/plugins/api.go VolumeDriver > volume/plugins/proxy.go

type volumeDriverCreateArgs struct {
	Name string
}

type volumeDriverCreateReturn struct {
	Err error
}

type volumeDriverRemoveArgs struct {
	Name string
}

type volumeDriverRemoveReturn struct {
	Err error
}

type volumeDriverPathArgs struct {
	Name string
}

type volumeDriverPathReturn struct {
	Mountpoint string
	Err        error
}

type volumeDriverMountArgs struct {
	Name string
}

type volumeDriverMountReturn struct {
	Mountpoint string
	Err        error
}

type volumeDriverUnmountArgs struct {
	Name string
}

type volumeDriverUnmountReturn struct {
	Err error
}

type volumeDriverProxy struct {
	client *plug.Client
}

func (pp *volumeDriverProxy) Create(name string) error {
	args := volumeDriverCreateArgs{name}
	var ret volumeDriverCreateReturn
	err := pp.client.Call("VolumeDriver.Create", args, &ret)
	if err != nil {
		return err
	}
	return ret.Err
}

func (pp *volumeDriverProxy) Remove(name string) error {
	args := volumeDriverRemoveArgs{name}
	var ret volumeDriverRemoveReturn
	err := pp.client.Call("VolumeDriver.Remove", args, &ret)
	if err != nil {
		return err
	}
	return ret.Err
}

func (pp *volumeDriverProxy) Path(name string) (string, error) {
	args := volumeDriverPathArgs{name}
	var ret volumeDriverPathReturn
	if err := pp.client.Call("VolumeDriver.Path", args, &ret); err != nil {
		return "", err
	}
	return ret.Mountpoint, ret.Err
}

func (pp *volumeDriverProxy) Mount(name string) (string, error) {
	args := volumeDriverMountArgs{name}
	var ret volumeDriverMountReturn
	if err = pp.client.Call("VolumeDriver.Mount", args, &ret); err != nil {
		return "", err
	}
	return ret.Mountpoint, ret.Err
}

func (pp *volumeDriverProxy) Unmount(name string) error {
	args := volumeDriverUnmountArgs{name}
	var ret volumeDriverUnmountReturn
	err := pp.client.Call("VolumeDriver.Unmount", args, &ret)
	if err != nil {
		return err
	}
	return ret.Err
}
