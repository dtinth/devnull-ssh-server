package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// The two requests this server makes of an SSH agent, from
// https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent
const (
	agentFailure           = 5
	agentRequestIdentities = 11
	agentIdentitiesAnswer  = 12
	agentSignRequest       = 13
	agentSignResponse      = 14
)

// maxAgentFrame caps one answer from the agent: a list of keys or a signature is a few KB. x/crypto's own client
// allocates whatever size the agent announces (up to 16 MiB) before any of it arrives, which a hostile agent could use
// to make the server hold memory, so this server speaks the protocol itself.
const maxAgentFrame = 256 << 10

// agentSigner is the part of an agent that signs, which x/crypto's in-memory keyring also has, for the tests.
type agentSigner interface {
	SignWithFlags(key gossh.PublicKey, data []byte, flags agent.SignatureFlags) (*gossh.Signature, error)
}

// agentClient lists the keys of an agent and has it sign, over a connection to it.
type agentClient struct {
	conn io.ReadWriter
}

func (c *agentClient) call(request []byte) ([]byte, error) {
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(request)))
	if _, err := c.conn.Write(append(frame, request...)); err != nil {
		return nil, err
	}

	var length [4]byte
	if _, err := io.ReadFull(c.conn, length[:]); err != nil {
		return nil, err
	}

	size := binary.BigEndian.Uint32(length[:])
	if size == 0 || size > maxAgentFrame {
		return nil, fmt.Errorf("agent answer of %d bytes", size)
	}

	answer := make([]byte, size)
	if _, err := io.ReadFull(c.conn, answer); err != nil {
		return nil, err
	}

	if answer[0] == agentFailure {
		return nil, errors.New("the agent refused")
	}

	return answer, nil
}

// Keys lists the agent's keys, skipping any this server can't parse.
func (c *agentClient) Keys() ([]gossh.PublicKey, error) {
	answer, err := c.call([]byte{agentRequestIdentities})
	if err != nil {
		return nil, err
	}
	if answer[0] != agentIdentitiesAnswer || len(answer) < 5 {
		return nil, errors.New("unexpected agent answer")
	}

	count := binary.BigEndian.Uint32(answer[1:5])
	rest := answer[5:]

	var keys []gossh.PublicKey
	for i := uint32(0); i < count; i++ {
		var entry struct {
			Blob    string
			Comment string
			Rest    []byte `ssh:"rest"`
		}
		if err := gossh.Unmarshal(rest, &entry); err != nil {
			return nil, errors.New("malformed agent answer")
		}
		rest = entry.Rest

		if key, err := gossh.ParsePublicKey([]byte(entry.Blob)); err == nil {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

func (c *agentClient) SignWithFlags(key gossh.PublicKey, data []byte, flags agent.SignatureFlags) (*gossh.Signature, error) {
	request := append([]byte{agentSignRequest}, gossh.Marshal(struct {
		Blob  string
		Data  string
		Flags uint32
	}{string(key.Marshal()), string(data), uint32(flags)})...)

	answer, err := c.call(request)
	if err != nil {
		return nil, err
	}
	if answer[0] != agentSignResponse {
		return nil, errors.New("unexpected agent answer")
	}

	var response struct{ Signature string }
	if err := gossh.Unmarshal(answer[1:], &response); err != nil {
		return nil, errors.New("malformed agent answer")
	}

	var signature gossh.Signature
	if err := gossh.Unmarshal([]byte(response.Signature), &signature); err != nil {
		return nil, errors.New("malformed signature from the agent")
	}

	return &signature, nil
}
