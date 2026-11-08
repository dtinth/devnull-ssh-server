package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"charm.land/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// maxBodyBytes caps what is read from stdin: far more than dev-null.sh lets a commit be.
const maxBodyBytes = 64 << 10

// usage takes the ssh command that reaches this server, then its host name and port.
const usage = `Commit to dev-null.sh with your own SSH key, through your forwarded SSH agent:

  %[1]s commit 'Hello world!'
  echo 'Hello world!' | %[1]s commit
  %[1]s commit --reply 0be0130 'Agreed!'

Your agent signs with the key of yours that is on your GitHub account.
-A forwards your agent. To leave it out, put this in ~/.ssh/config:

  Host devnull
    HostName %[2]s
    Port %[3]s
    ForwardAgent yes

Then: ssh devnull commit 'Hello world!'
`

type config struct {
	// DevnullURL is where commits go, like https://dev-null.sh.
	DevnullURL string
	// Name is how this server is shown in the usage, like "dev-null.example.com".
	Name string
	// Port is the port clients connect to, shown in the usage; 22 when empty.
	Port string
	// HTTPClient sends the commits; newHTTPClient when nil.
	HTTPClient *http.Client
	// Now tells the time, for the signed timestamp; time.Now when nil.
	Now func() time.Time
}

func newServer(cfg config, hostKey gossh.Signer) *ssh.Server {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = newHTTPClient()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	server := &ssh.Server{
		Handler: func(s ssh.Session) {
			_ = s.Exit(handle(cfg, s))
		},
		// Anyone may log in with any key: the key only gets to sign a commit, and dev-null.sh decides whose it is.
		PublicKeyHandler: func(ssh.Context, ssh.PublicKey) bool { return true },
		HandshakeTimeout: 30 * time.Second,
		IdleTimeout:      2 * time.Minute,
		MaxTimeout:       10 * time.Minute,
	}
	server.AddHostKey(hostKey)

	return server
}

func (cfg config) port() string {
	if cfg.Port == "" {
		return "22"
	}

	return cfg.Port
}

// sshCommand is the command that reaches this server with the agent forwarded, like "ssh -A -p 2222 example.com".
func (cfg config) sshCommand() string {
	if cfg.port() == "22" {
		return "ssh -A " + cfg.Name
	}

	return "ssh -A -p " + cfg.port() + " " + cfg.Name
}

// handle runs one SSH session, and returns its exit status.
func handle(cfg config, s ssh.Session) int {
	command, rest := nextWord(s.RawCommand())
	if command != "commit" {
		fmt.Fprintf(s.Stderr(), usage, cfg.sshCommand(), cfg.Name, cfg.port())
		if command == "" || command == "help" {
			return 0
		}

		return 2
	}

	replyTo, message, err := parseCommitArgs(rest)
	if err != nil {
		return fail(s, err.Error())
	}

	if !ssh.AgentRequested(s) {
		return fail(s, "Your SSH agent is not forwarded. Connect with ssh -A, or set ForwardAgent yes in ~/.ssh/config.")
	}

	if message == nil {
		// A terminal sends Ctrl-D as a byte, not as the end of input, so the message would never end.
		if _, _, isPty := s.Pty(); isPty {
			return fail(s, "Pass the message as an argument, or pipe it in: echo 'Hello world!' | "+cfg.sshCommand()+" commit")
		}

		body, err := io.ReadAll(io.LimitReader(s, maxBodyBytes+1))
		if err != nil {
			return fail(s, "Could not read the commit message.")
		}
		if len(body) > maxBodyBytes {
			return fail(s, "The commit message is too long.")
		}
		message = body
	}

	if !utf8.Valid(message) {
		return fail(s, "The commit message is not UTF-8 text.")
	}
	if strings.TrimSpace(string(message)) == "" {
		return fail(s, "Aborting commit due to empty commit message.")
	}

	ctx, cancel := context.WithTimeout(s.Context(), 30*time.Second)
	defer cancel()

	keyring, closeAgent, err := openAgent(ctx, s)
	if err != nil {
		return fail(s, "Could not reach your forwarded SSH agent.")
	}
	defer closeAgent()

	key, err := chooseKey(ctx, cfg, keyring, s.PublicKey())
	if err != nil {
		return fail(s, err.Error())
	}

	payload, err := commitPayload(cfg.Now(), replyTo, string(message))
	if err != nil {
		return fail(s, "Could not make a nonce.")
	}

	signature, err := signSSHSIG(keyring, key, commitNamespace, payload)
	// The agent is needed for nothing else: stop talking to it before the commit is even sent.
	closeAgent()
	if err != nil {
		return fail(s, err.Error())
	}

	answer, err := postCommit(ctx, cfg.HTTPClient, cfg.DevnullURL, payload, signature)
	slog.Info("commit", "remote", s.RemoteAddr().String(), "key", gossh.FingerprintSHA256(key), "ok", err == nil)
	if err != nil {
		return fail(s, err.Error())
	}

	fmt.Fprintln(s, answer)

	return 0
}

// parseCommitArgs reads `[--reply <hash or link>] [--] [message]` from what follows "commit" in the command line. The
// message is the rest of the line as the client sent it: ssh joins its arguments with spaces and drops the shell's
// quotes, so it is not split into words again (an apostrophe in it would not parse). It is nil when it is to be read
// from stdin.
func parseCommitArgs(rest string) (replyTo string, message []byte, err error) {
	for {
		word, after := nextWord(rest)
		switch word {
		case "--reply":
			ref, afterRef := nextWord(after)
			if ref == "" {
				return "", nil, errors.New("Usage: commit --reply <commit hash or link> 'Your reply'")
			}
			if replyTo != "" {
				return "", nil, errors.New("--reply can only be given once.")
			}
			if !validReplyTo(ref) {
				return "", nil, errors.New("--reply takes the hash of a commit or its link.")
			}
			replyTo, rest = ref, afterRef
			continue
		case "--":
			rest = after
		}

		break
	}

	rest = strings.TrimLeft(rest, " \t")
	if rest == "" {
		return replyTo, nil, nil
	}

	return replyTo, []byte(rest), nil
}

// nextWord splits off the first word of a command line.
func nextWord(line string) (word, rest string) {
	line = strings.TrimLeft(line, " \t")
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		return line[:i], line[i:]
	}

	return line, ""
}

// chooseKey picks the key to sign with among the agent's keys, as the commit script does: dev-null.sh is asked which
// of them is on a user's GitHub account, and the one the client logged in with is offered first. ssh logs in with the
// first key its agent holds, which need not be the GitHub one.
func chooseKey(ctx context.Context, cfg config, keyring *agentClient, login gossh.PublicKey) (gossh.PublicKey, error) {
	keys, err := keyring.Keys()
	if err != nil {
		return nil, errors.New("Could not list the keys of your SSH agent.")
	}

	var candidates []gossh.PublicKey
	for _, key := range keys {
		if key.Type() != gossh.KeyAlgoED25519 && key.Type() != gossh.KeyAlgoRSA {
			continue
		}

		if login != nil && bytes.Equal(key.Marshal(), login.Marshal()) {
			candidates = append([]gossh.PublicKey{key}, candidates...)
		} else {
			candidates = append(candidates, key)
		}
	}

	if len(candidates) == 0 {
		return nil, errors.New("Your forwarded SSH agent holds no Ed25519 or RSA key. Add one with ssh-add.")
	}
	if len(candidates) > maxCandidates {
		candidates = candidates[:maxCandidates]
	}

	return lookupKey(ctx, cfg.HTTPClient, cfg.DevnullURL, candidates)
}

// maxCandidates caps how many of an agent's keys are looked up.
const maxCandidates = 32

// openAgent talks to the client's forwarded agent over its own SSH channel, without a socket on this machine. The
// channel is closed when ctx ends, so an agent that stalls can't make the server wait.
func openAgent(ctx context.Context, s ssh.Session) (*agentClient, func(), error) {
	conn, ok := s.Context().Value(ssh.ContextKeyConn).(gossh.Conn)
	if !ok {
		return nil, nil, errors.New("no SSH connection")
	}

	channel, requests, err := conn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		return nil, nil, err
	}
	go gossh.DiscardRequests(requests)

	var once sync.Once
	closeChannel := func() { once.Do(func() { _ = channel.Close() }) }
	stop := context.AfterFunc(ctx, closeChannel)

	return &agentClient{conn: channel}, func() { stop(); closeChannel() }, nil
}

func fail(s ssh.Session, message string) int {
	fmt.Fprintln(s.Stderr(), "devnull: "+sanitize(message))

	return 1
}
