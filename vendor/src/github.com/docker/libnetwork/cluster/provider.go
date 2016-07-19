package cluster

// Provider provides clustering config details
type Provider interface {
	IsManager() bool
	IsAgent() bool
	GetAdvertiseAddress() string
	GetRemoteAddress() string
	ListenClusterEvents() <-chan struct{}
}
