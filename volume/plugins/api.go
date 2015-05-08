package plugins

import (
	"github.com/docker/docker/pkg/plugins"
	"github.com/docker/docker/volume"
)

func init() {
	plugins.Handle("VolumeDriver", func(name string, client *plugins.Client) {
		proxy := &volumeDriverProxy{client}
		adapter := &volumeDriverAdapter{name, proxy}
		volume.Drivers.Register(adapter, name)
	})
}

type VolumeDriver interface {
	Create(name string) (err error)
	Remove(name string) (err error)
	Path(name string) (mountpoint string, err error)
	Mount(name string) (mountpoint string, err error)
	Unmount(name string) (err error)
}
