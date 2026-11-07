// devnull-ssh is an SSH server that commits to dev-null.sh for anyone, with their own key:
//
//	echo 'Hello world!' | ssh -A <host> commit
//
// The key they log in with signs the commit through their forwarded SSH agent, so no key ever reaches this server.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"charm.land/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// A commit takes a few seconds, so these leave plenty of room for real use.
const (
	maxConnections           = 64
	maxConnectionsPerAddress = 4
)

func main() {
	if err := run(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run() error {
	listen := env("DEVNULL_SSH_LISTEN", ":2222")
	devnullURL := env("DEVNULL_URL", "https://dev-null.sh")
	hostKeyPath := env("DEVNULL_SSH_HOST_KEY", "data/ssh_host_ed25519_key")

	if err := checkBaseURL(devnullURL); err != nil {
		return err
	}

	hostKey, err := loadOrCreateHostKey(hostKeyPath)
	if err != nil {
		return err
	}

	server := newServer(config{DevnullURL: devnullURL, Name: env("DEVNULL_SSH_NAME", "<host>")}, hostKey)

	inner, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	listener := newLimitListener(inner, maxConnections, maxConnectionsPerAddress)

	slog.Info("listening", "address", listener.Addr().String(), "devnull", devnullURL, "host_key", gossh.FingerprintSHA256(hostKey.PublicKey()))

	err = server.Serve(listener)
	if errors.Is(err, ssh.ErrServerClosed) {
		return nil
	}

	return err
}

// loadOrCreateHostKey reads the server's host key, making an Ed25519 one on the first start.
func loadOrCreateHostKey(path string) (gossh.Signer, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		data, err = createHostKey(path)
	}
	if err != nil {
		return nil, err
	}

	return gossh.ParsePrivateKey(data)
}

func createHostKey(path string) ([]byte, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	block, err := gossh.MarshalPrivateKey(private, "devnull-ssh host key")
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(block)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}

	// O_EXCL: never overwrite a key that appeared in the meantime.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return nil, err
	}

	return data, file.Close()
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}

	return fallback
}
