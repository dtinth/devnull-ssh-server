package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// servedAgent connects an agentClient to x/crypto's agent server over a pipe.
func servedAgent(t *testing.T, keyring agent.Agent) *agentClient {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	go func() { _ = agent.ServeAgent(keyring, server) }()

	return &agentClient{conn: client}
}

func TestAgentClientListsAndSigns(t *testing.T) {
	for _, k := range testKeys(t) {
		t.Run(k.name, func(t *testing.T) {
			keyring, public := keyringWith(t, k.private)
			client := servedAgent(t, keyring)

			keys, err := client.Keys()
			if err != nil || len(keys) != 1 || !bytes.Equal(keys[0].Marshal(), public.Marshal()) {
				t.Fatalf("got %v %v", keys, err)
			}

			signature, err := signSSHSIG(client, public, commitNamespace, []byte("hello"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifySSHSIG([]byte("hello"), signature, commitNamespace); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// fakeConn answers every request with the same bytes.
type fakeConn struct {
	io.Reader
}

func (fakeConn) Write(p []byte) (int, error) { return len(p), nil }

func TestAgentClientRefusesAHugeAnswer(t *testing.T) {
	// A hostile agent announces 16 MiB and then sends nothing: the client must not wait for it, nor allocate it.
	announce := binary.BigEndian.AppendUint32(nil, 16<<20)
	client := &agentClient{conn: fakeConn{bytes.NewReader(announce)}}

	if _, err := client.Keys(); err == nil || !strings.Contains(err.Error(), "agent answer of") {
		t.Fatalf("got %v", err)
	}
}

func TestAgentClientReportsARefusal(t *testing.T) {
	failure := append(binary.BigEndian.AppendUint32(nil, 1), agentFailure)
	client := &agentClient{conn: fakeConn{bytes.NewReader(failure)}}

	signer, err := gossh.NewSignerFromKey(ed25519PrivateKey(t))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.SignWithFlags(signer.PublicKey(), []byte("x"), 0); err == nil {
		t.Fatal("no error")
	}
}
