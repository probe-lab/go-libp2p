package config

import (
	"context"

	basichost "github.com/libp2p/go-libp2p/p2p/host/basic"
	routed "github.com/libp2p/go-libp2p/p2p/host/routed"

	"go.uber.org/fx"
)

type ClosableBasicHost struct {
	*fx.App
	*basichost.BasicHost
}

func (h *ClosableBasicHost) Close() error {
	_ = h.App.Stop(context.Background())
	return h.BasicHost.Close()
}

type closableRoutedHost struct {
	// ClosableBasicHost is embedded here so that interface assertions on
	// BasicHost exported methods work correctly.
	ClosableBasicHost
	*routed.RoutedHost
}

func (h *closableRoutedHost) Close() error {
	_ = h.App.Stop(context.Background())
	// The routed host will close the basic host
	return h.RoutedHost.Close()
}
