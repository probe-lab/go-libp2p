package swarm

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/transport"
	"github.com/libp2p/go-libp2p/p2p/host/eventbus"
	"github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoremem"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

var errPartialRefused = errors.New("connection refused")

// partialTransport stands in for TCP. A dial to port 1 fails at once, and a
// dial to any other port blocks until its context ends.
type partialTransport struct{}

func (partialTransport) Dial(ctx context.Context, raddr ma.Multiaddr, _ peer.ID) (transport.CapableConn, error) {
	if port, _ := raddr.ValueForProtocol(ma.P_TCP); port == "1" {
		return nil, errPartialRefused
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (partialTransport) CanDial(addr ma.Multiaddr) bool {
	_, err := addr.ValueForProtocol(ma.P_TCP)
	return err == nil
}

func (partialTransport) Listen(ma.Multiaddr) (transport.Listener, error) {
	return nil, errors.New("not supported")
}

func (partialTransport) Protocols() []int { return []int{ma.P_TCP} }

func (partialTransport) Proxy() bool { return false }

func TestDialPeerReportsDialErrorsWhenContextEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		priv, id := newPeer(t)
		ps, err := pstoremem.NewPeerstore()
		require.NoError(t, err)
		defer ps.Close()
		require.NoError(t, ps.AddPrivKey(id, priv))
		require.NoError(t, ps.AddPubKey(id, priv.GetPublic()))

		refused := ma.StringCast("/ip4/192.0.2.1/tcp/1")
		inProgress := ma.StringCast("/ip4/192.0.2.1/tcp/2")
		notDialed := ma.StringCast("/ip4/192.0.2.1/tcp/3")

		// dial notDialed long after the dial context ends
		ranker := func(addrs []ma.Multiaddr) []network.AddrDelay {
			delays := make([]network.AddrDelay, 0, len(addrs))
			for _, a := range addrs {
				var d time.Duration
				if a.Equal(notDialed) {
					d = time.Hour
				}
				delays = append(delays, network.AddrDelay{Addr: a, Delay: d})
			}
			return delays
		}

		s, err := NewSwarm(id, ps, eventbus.NewBus(), WithDialRanker(ranker))
		require.NoError(t, err)
		defer s.Close()
		require.NoError(t, s.AddTransport(partialTransport{}))

		_, remote := newPeer(t)
		s.Peerstore().AddAddrs(remote, []ma.Multiaddr{refused, inProgress, notDialed}, peerstore.TempAddrTTL)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err = s.DialPeer(ctx, remote)

		require.ErrorIs(t, err, context.DeadlineExceeded)
		var derr *DialError
		require.ErrorAs(t, err, &derr)
		require.ErrorIs(t, derr.Cause, context.DeadlineExceeded)

		causes := map[string]error{}
		for _, te := range derr.DialErrors {
			causes[te.Address.String()] = te.Cause
		}
		require.Len(t, causes, 2)
		require.ErrorIs(t, causes[refused.String()], errPartialRefused)
		require.ErrorIs(t, causes[inProgress.String()], context.DeadlineExceeded)
		require.NotContains(t, causes, notDialed.String())
	})
}

func TestDialPeerReturnsContextErrorWithoutDials(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		priv, id := newPeer(t)
		ps, err := pstoremem.NewPeerstore()
		require.NoError(t, err)
		defer ps.Close()
		require.NoError(t, ps.AddPrivKey(id, priv))
		require.NoError(t, ps.AddPubKey(id, priv.GetPublic()))

		s, err := NewSwarm(id, ps, eventbus.NewBus())
		require.NoError(t, err)
		defer s.Close()
		require.NoError(t, s.AddTransport(partialTransport{}))

		_, remote := newPeer(t)
		s.Peerstore().AddAddrs(remote, []ma.Multiaddr{ma.StringCast("/ip4/192.0.2.1/tcp/2")}, peerstore.TempAddrTTL)

		// the context has ended before the dial starts
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = s.DialPeer(ctx, remote)
		require.ErrorIs(t, err, context.Canceled)
	})
}
