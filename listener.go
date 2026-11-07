package main

import (
	"net"
	"sync"
)

// limitListener drops connections over a total, and over a number per client address, so a few clients can't hold
// every handshake and session the server has.
type limitListener struct {
	net.Listener
	total, perAddress int

	mu     sync.Mutex
	open   int
	byAddr map[string]int
}

func newLimitListener(l net.Listener, total, perAddress int) *limitListener {
	return &limitListener{Listener: l, total: total, perAddress: perAddress, byAddr: map[string]int{}}
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		addr := hostOf(conn.RemoteAddr())

		l.mu.Lock()
		allowed := l.open < l.total && l.byAddr[addr] < l.perAddress
		if allowed {
			l.open++
			l.byAddr[addr]++
		}
		l.mu.Unlock()

		if !allowed {
			_ = conn.Close()
			continue
		}

		return &limitedConn{Conn: conn, release: func() { l.release(addr) }}, nil
	}
}

func (l *limitListener) release(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.open--
	if l.byAddr[addr]--; l.byAddr[addr] <= 0 {
		delete(l.byAddr, addr)
	}
}

func hostOf(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}

	return host
}

// limitedConn gives its slot back once, when it is closed.
type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)

	return err
}
