package main

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestLimitListenerCapsConnectionsPerAddress(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := newLimitListener(inner, 10, 2)
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan net.Conn, 10)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	dial := func() net.Conn {
		conn, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}

	nextAccepted := func() net.Conn {
		select {
		case conn := <-accepted:
			return conn
		case <-time.After(2 * time.Second):
			t.Fatal("no connection was accepted")
			return nil
		}
	}

	dial()
	dial()
	first := nextAccepted()
	nextAccepted()

	// The third from the same address is closed at once.
	third := dial()
	_ = third.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := third.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("third connection: got %v, want EOF", err)
	}

	// Closing one frees its slot for the next.
	_ = first.Close()
	dial()
	nextAccepted()
}
