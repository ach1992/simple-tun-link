//go:build linux

package spoof

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// PathFrameReceiver reports the locally addressed real endpoint in addition
// to the untrusted observed outer Source and profile. Authenticated feedback
// may then identify the exact (Source,profile,destination) route that worked.
type PathFrameReceiver interface {
	FrameReceiver
	ReadPathFrame([]byte) (int, netip.AddrPort, netip.AddrPort, string, error)
}

type endpointPart struct {
	receiver FrameReceiver
	endpoint netip.AddrPort
}

type pathRead struct {
	data             []byte
	source, endpoint netip.AddrPort
	profile          string
	err              error
}

// MultiEndpointReceiver owns only the listeners for the explicitly paired
// local IPv4:port endpoints; partial alternatives are reported, not fabricated.
type MultiEndpointReceiver struct {
	parts          []endpointPart
	active, failed []string
	frames         chan pathRead
	stop           chan struct{}
	once           sync.Once
	wg             sync.WaitGroup
	deadline       time.Time
}

func OpenMultiEndpointReceiver(endpoints []netip.AddrPort, policy, device string) (*MultiEndpointReceiver, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("no explicit local Spoof receive endpoints")
	}
	r := &MultiEndpointReceiver{frames: make(chan pathRead, 128), stop: make(chan struct{})}
	for _, endpoint := range endpoints {
		receiver, err := OpenFrameReceiver(endpoint, policy, device)
		if err != nil {
			r.failed = append(r.failed, fmt.Sprintf("%s: %v", endpoint, err))
			continue
		}
		r.parts = append(r.parts, endpointPart{receiver, endpoint})
		if named, ok := receiver.(interface {
			AvailableProfiles() []string
			FailedProfiles() []string
		}); ok {
			for _, profile := range named.AvailableProfiles() {
				r.active = append(r.active, endpoint.String()+"/"+profile)
			}
			for _, failure := range named.FailedProfiles() {
				r.failed = append(r.failed, endpoint.String()+"/"+failure)
			}
		} else {
			chosen := policy
			if chosen == "" {
				chosen = ProfileUDP
			}
			r.active = append(r.active, endpoint.String()+"/"+chosen)
		}
	}
	if len(r.parts) == 0 {
		return nil, fmt.Errorf("all configured Spoof listeners failed: %v", r.failed)
	}
	for _, part := range r.parts {
		r.wg.Add(1)
		go func(part endpointPart) {
			defer r.wg.Done()
			buf := make([]byte, 65535)
			for {
				select {
				case <-r.stop:
					return
				default:
				}
				_ = part.receiver.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
				var n int
				var source netip.AddrPort
				var profile string
				var err error
				if named, ok := part.receiver.(ProfileFrameReceiver); ok {
					n, source, profile, err = named.ReadProfileFrame(buf)
				} else {
					n, source, err = part.receiver.ReadFrame(buf)
					profile = policy
					if profile == "" {
						profile = ProfileUDP
					}
				}
				if err != nil {
					if e, ok := err.(net.Error); ok && e.Timeout() {
						continue
					}
					if errors.Is(err, os.ErrDeadlineExceeded) {
						continue
					}
					select {
					case r.frames <- pathRead{err: fmt.Errorf("listener %s: %w", part.endpoint, err)}:
					case <-r.stop:
					}
					return
				}
				select {
				case r.frames <- pathRead{data: append([]byte(nil), buf[:n]...),
					source: source, endpoint: part.endpoint, profile: profile}:
				case <-r.stop:
					return
				}
			}
		}(part)
	}
	return r, nil
}

func (r *MultiEndpointReceiver) SetReadDeadline(t time.Time) error { r.deadline = t; return nil }
func (r *MultiEndpointReceiver) AvailableProfiles() []string {
	return append([]string(nil), r.active...)
}
func (r *MultiEndpointReceiver) FailedProfiles() []string { return append([]string(nil), r.failed...) }
func (r *MultiEndpointReceiver) ReadPathFrame(dst []byte) (int, netip.AddrPort, netip.AddrPort, string, error) {
	for {
		remaining := time.Until(r.deadline)
		if r.deadline.IsZero() || remaining <= 0 {
			return 0, netip.AddrPort{}, netip.AddrPort{}, "", os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(remaining)
		select {
		case <-r.stop:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return 0, netip.AddrPort{}, netip.AddrPort{}, "", os.ErrClosed
		case <-timer.C:
			return 0, netip.AddrPort{}, netip.AddrPort{}, "", os.ErrDeadlineExceeded
		case frame := <-r.frames:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			if frame.err != nil {
				return 0, netip.AddrPort{}, netip.AddrPort{}, "", frame.err
			}
			if len(frame.data) > len(dst) {
				continue
			}
			copy(dst, frame.data)
			return len(frame.data), frame.source, frame.endpoint, frame.profile, nil
		}
	}
}
func (r *MultiEndpointReceiver) ReadFrame(dst []byte) (int, netip.AddrPort, error) {
	n, s, _, _, err := r.ReadPathFrame(dst)
	return n, s, err
}
func (r *MultiEndpointReceiver) Close() error {
	var first error
	r.once.Do(func() {
		close(r.stop)
		for _, part := range r.parts {
			if err := part.receiver.Close(); err != nil && first == nil {
				first = err
			}
		}
		r.wg.Wait()
	})
	return first
}

var _ PathFrameReceiver = (*MultiEndpointReceiver)(nil)
