package plugins

import (
	"fmt"
	"sync"

	"github.com/Sirupsen/logrus"
)

var (
	activePlugins    = &plugins{plugins: make(map[string]*Plugin)}
	extpointHandlers = make(map[string]func(string, *Client))
)

type plugins struct {
	sync.Mutex
	plugins map[string]*Plugin
}

type Manifest struct {
	Implements []string
}

type Plugin struct {
	Name     string
	Addr     string
	Client   *Client
	Manifest *Manifest
}

func (p *Plugin) Activate() error {
	activePlugins.Lock()
	defer activePlugins.Unlock()
	_, exists := activePlugins.plugins[p.Name]
	if exists {
		return fmt.Errorf("Plugin already activated")
	}

	var m *Manifest
	p.Client = NewClient(p.Addr)
	err := p.Client.Call("Plugin.Activate", nil, m)
	if err != nil {
		return err
	}
	p.Manifest = m

	for _, iface := range m.Implements {
		handler, handled := extpointHandlers[iface]
		if !handled {
			continue
		}
		handler(p.Name, p.Client)
	}

	activePlugins.plugins[p.Name] = p
	return nil
}

func Load() error {
	registry := newLocalRegistry("")
	plugins, err := registry.Plugins()
	if err != nil {
		return err
	}
	for _, plugin := range plugins {
		err := plugin.Activate()
		if err != nil {
			// intentionally not bubbling
			// activation errors up.
			logrus.Warn("Plugin load error:", err)
		}
	}
	return nil
}

func Get(name string) (*Plugin, error) {
	activePlugins.Lock()
	plugin, exists := activePlugins.plugins[name]
	activePlugins.Unlock()
	if !exists {
		registry := newLocalRegistry("")
		plugin, err := registry.Plugin(name)
		if err != nil {
			return nil, err
		}
		err = plugin.Activate()
		if err != nil {
			return nil, err
		}
		return plugin, nil
	}
	return plugin, nil
}

func Active() []*Plugin {
	activePlugins.Lock()
	defer activePlugins.Unlock()
	var plugins []*Plugin
	for _, plugin := range activePlugins.plugins {
		plugins = append(plugins, plugin)
	}
	return plugins
}

func Handle(iface string, fn func(string, *Client)) {
	extpointHandlers[iface] = fn
}
