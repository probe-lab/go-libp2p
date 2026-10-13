package swarm

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// dialWorkerFunc is used by dialSync to spawn a new dial worker
type dialWorkerFunc func(peer.ID, <-chan dialRequest)

// errConcurrentDialSuccessful is used to signal that a concurrent dial succeeded
var errConcurrentDialSuccessful = errors.New("concurrent dial successful")

const (
	// cancelSendRetries is the number of times a caller whose context ended
	// retries to hand its cancel request to a busy dial worker.
	cancelSendRetries = 3
	// cancelSendRetryDelay is the pause between those retries.
	cancelSendRetryDelay = time.Millisecond
)

// newDialSync constructs a new dialSync
func newDialSync(worker dialWorkerFunc) *dialSync {
	return &dialSync{
		dials:      make(map[peer.ID]*activeDial),
		dialWorker: worker,
	}
}

// dialSync is a dial synchronization helper that ensures that at most one dial
// to any given peer is active at any given time.
type dialSync struct {
	mutex      sync.Mutex
	dials      map[peer.ID]*activeDial
	dialWorker dialWorkerFunc
}

type activeDial struct {
	refCnt int

	ctx         context.Context
	cancelCause func(error)

	reqch chan dialRequest
}

func (ad *activeDial) dial(ctx context.Context) (*Conn, error) {
	dialCtx := ad.ctx

	if forceDirect, reason := network.GetForceDirectDial(ctx); forceDirect {
		dialCtx = network.WithForceDirectDial(dialCtx, reason)
	}
	if disableBackoff, reason := network.GetDisableBackoff(ctx); disableBackoff {
		dialCtx = network.WithDisableBackoff(dialCtx, reason)
	}
	if simConnect, isClient, reason := network.GetSimultaneousConnect(ctx); simConnect {
		dialCtx = network.WithSimultaneousConnect(dialCtx, isClient, reason)
	}

	resch := make(chan dialResponse, 1)
	select {
	case ad.reqch <- dialRequest{ctx: dialCtx, resch: resch}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	select {
	case res := <-resch:
		return res.conn, res.err
	case <-ctx.Done():
		// The dial may still be running. Ask the worker for the results it has
		// collected so far. Once the worker has taken the cancel request it
		// always answers on resch: with the dial's own response if it
		// completed in the meantime, or with a DialError that wraps the
		// context error and lists the per-address results.
		//
		// The send must not block without bound. The worker may be busy
		// delivering a connectedness event, and the consumer of that event
		// may be the caller of this very function. Waiting for the worker
		// would then deadlock. So the send is retried a few times with short
		// pauses. If the worker stays busy, the plain context error is
		// returned, marked with ErrDialResultsUnavailable.
		cancelReq := dialRequest{resch: resch, cancelErr: ctx.Err()}
		for attempt := 0; ; attempt++ {
			select {
			case ad.reqch <- cancelReq:
				res := <-resch
				return res.conn, res.err
			case res := <-resch:
				// the worker answered in the meantime
				return res.conn, res.err
			default:
			}
			if attempt == cancelSendRetries {
				return nil, fmt.Errorf("%w: %w", ErrDialResultsUnavailable, ctx.Err())
			}
			time.Sleep(cancelSendRetryDelay)
		}
	}
}

func (ds *dialSync) getActiveDial(p peer.ID) (*activeDial, error) {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	actd, ok := ds.dials[p]
	if !ok {
		// This code intentionally uses the background context. Otherwise, if the first call
		// to Dial is canceled, subsequent dial calls will also be canceled.
		ctx, cancel := context.WithCancelCause(context.Background())
		actd = &activeDial{
			ctx:         ctx,
			cancelCause: cancel,
			reqch:       make(chan dialRequest),
		}
		go ds.dialWorker(p, actd.reqch)
		ds.dials[p] = actd
	}
	// increase ref count before dropping mutex
	actd.refCnt++
	return actd, nil
}

// Dial initiates a dial to the given peer if there are none in progress
// then waits for the dial to that peer to complete.
func (ds *dialSync) Dial(ctx context.Context, p peer.ID) (*Conn, error) {
	ad, err := ds.getActiveDial(p)
	if err != nil {
		return nil, err
	}

	conn, err := ad.dial(ctx)

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	ad.refCnt--
	if ad.refCnt == 0 {
		if err == nil {
			ad.cancelCause(errConcurrentDialSuccessful)
		} else {
			ad.cancelCause(err)
		}
		close(ad.reqch)
		delete(ds.dials, p)
	}

	return conn, err
}
