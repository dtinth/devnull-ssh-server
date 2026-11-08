package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// fakeDevnull answers like dev-null.sh's /api/cli/key-lookups and /api/cli/commits, and remembers the commits whose
// signature checks out.
type fakeDevnull struct {
	mu      sync.Mutex
	commits []receivedCommit
	refuse  string
	// onGitHub holds the keys (in the wire format) that are on a user's GitHub account; every key is when nil.
	onGitHub map[string]bool
}

type receivedCommit struct {
	key     gossh.PublicKey
	payload string
}

func (f *fakeDevnull) knows(key gossh.PublicKey) bool {
	return f.onGitHub == nil || f.onGitHub[string(key.Marshal())]
}

func (f *fakeDevnull) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/api/cli/key-lookups" {
		body, _ := io.ReadAll(r.Body)
		for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
			key, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
			if err == nil && f.knows(key) {
				_, _ = w.Write(gossh.MarshalAuthorizedKey(key))
				return
			}
		}

		http.Error(w, "None of these SSH keys is on the GitHub account of a /dev/null user.", http.StatusUnprocessableEntity)
		return
	}

	if r.Method != http.MethodPost || r.URL.Path != "/api/cli/commits" {
		http.NotFound(w, r)
		return
	}

	payload, _ := io.ReadAll(r.Body)
	key, err := verifySSHSIG(payload, r.Header.Get("X-SSH-Signature"), commitNamespace)
	if err != nil {
		http.Error(w, "Invalid signature.", http.StatusUnauthorized)
		return
	}
	if !f.knows(key) {
		http.Error(w, "This SSH key is not on the GitHub account of a /dev/null user.", http.StatusUnauthorized)
		return
	}
	if f.refuse != "" {
		http.Error(w, f.refuse, http.StatusUnprocessableEntity)
		return
	}

	f.mu.Lock()
	f.commits = append(f.commits, receivedCommit{key, string(payload)})
	f.mu.Unlock()

	_, _ = io.WriteString(w, "Committed: https://dev-null.sh/@you/commits/1\n")
}

type harness struct {
	t       *testing.T
	address string
	devnull *fakeDevnull
}

func startHarness(t *testing.T) *harness {
	t.Helper()

	devnull := &fakeDevnull{}
	web := httptest.NewServer(devnull)
	t.Cleanup(web.Close)

	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := gossh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	server := newServer(config{DevnullURL: web.URL, Name: "devnull.test", Now: func() time.Time { return time.Unix(1700000000, 0) }}, hostKey)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	return &harness{t, listener.Addr().String(), devnull}
}

type session struct {
	command   string
	stdin     string
	login     any   // the private key the client logs in with
	agentKeys []any // the keys the forwarded agent holds
	noForward bool
	pty       bool
}

type result struct {
	stdout, stderr string
	status         int
}

func (h *harness) run(r session) result {
	h.t.Helper()

	signer, err := gossh.NewSignerFromKey(r.login)
	if err != nil {
		h.t.Fatal(err)
	}

	client, err := gossh.Dial("tcp", h.address, &gossh.ClientConfig{
		User:            "anyone",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		h.t.Fatal(err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		h.t.Fatal(err)
	}
	defer sess.Close()

	if !r.noForward {
		keyring := agent.NewKeyring()
		for _, key := range r.agentKeys {
			if err := keyring.Add(agent.AddedKey{PrivateKey: key}); err != nil {
				h.t.Fatal(err)
			}
		}
		if err := agent.ForwardToAgent(client, keyring); err != nil {
			h.t.Fatal(err)
		}
		if err := agent.RequestAgentForwarding(sess); err != nil {
			h.t.Fatal(err)
		}
	}

	if r.pty {
		if err := sess.RequestPty("xterm", 24, 80, gossh.TerminalModes{}); err != nil {
			h.t.Fatal(err)
		}
	}

	var stdout, stderr bytes.Buffer
	sess.Stdin = strings.NewReader(r.stdin)
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	status := 0
	if err := sess.Run(r.command); err != nil {
		var exit *gossh.ExitError
		if !errors.As(err, &exit) {
			h.t.Fatal(err)
		}
		status = exit.ExitStatus()
	}

	return result{stdout.String(), stderr.String(), status}
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func publicOf(t *testing.T, private any) gossh.PublicKey {
	t.Helper()

	signer, err := gossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}

	return signer.PublicKey()
}

func TestCommitFromArguments(t *testing.T) {
	h := startHarness(t)
	key := newKey(t)

	// ssh joins its arguments with spaces and sends no quotes: the apostrophe arrives bare.
	got := h.run(session{command: "commit it's alive", login: key, agentKeys: []any{key}})

	if got.status != 0 || !strings.Contains(got.stdout, "Committed:") {
		t.Fatalf("got %+v", got)
	}
	if len(h.devnull.commits) != 1 {
		t.Fatalf("dev-null got %d commits", len(h.devnull.commits))
	}

	commit := h.devnull.commits[0]
	if !bytes.Equal(commit.key.Marshal(), publicOf(t, key).Marshal()) {
		t.Fatal("signed with another key")
	}

	lines := strings.SplitN(commit.payload, "\n", 4)
	if len(lines) != 4 || lines[0] != "1700000000" || len(lines[1]) != 32 || lines[2] != "" || lines[3] != "it's alive" {
		t.Fatalf("payload %q", commit.payload)
	}
}

func TestCommitFromStdinAsAReply(t *testing.T) {
	h := startHarness(t)
	key := newKey(t)

	got := h.run(session{command: "commit --reply 0be0130", stdin: "Agreed!\nTwo lines.\n", login: key, agentKeys: []any{key}})

	if got.status != 0 {
		t.Fatalf("got %+v", got)
	}

	lines := strings.SplitN(h.devnull.commits[0].payload, "\n", 4)
	if lines[2] != "0be0130" || lines[3] != "Agreed!\nTwo lines.\n" {
		t.Fatalf("payload %q", h.devnull.commits[0].payload)
	}
}

func TestPrefersTheLoginKeyAmongGitHubKeys(t *testing.T) {
	h := startHarness(t)
	login, other := newKey(t), newKey(t)

	got := h.run(session{command: "commit hi", login: login, agentKeys: []any{other, login}})

	if got.status != 0 || !bytes.Equal(h.devnull.commits[0].key.Marshal(), publicOf(t, login).Marshal()) {
		t.Fatalf("got %+v", got)
	}
}

// ssh logs in with the first key of the agent, which may be a work key that GitHub has never seen.
func TestSignsWithTheAgentKeyThatIsOnGitHub(t *testing.T) {
	h := startHarness(t)
	work, github := newKey(t), newKey(t)
	h.devnull.onGitHub = map[string]bool{string(publicOf(t, github).Marshal()): true}

	got := h.run(session{command: "commit hi", login: work, agentKeys: []any{work, github}})

	if got.status != 0 || !bytes.Equal(h.devnull.commits[0].key.Marshal(), publicOf(t, github).Marshal()) {
		t.Fatalf("got %+v", got)
	}
}

func TestNoAgentKeyOnGitHub(t *testing.T) {
	h := startHarness(t)
	key := newKey(t)
	h.devnull.onGitHub = map[string]bool{}

	got := h.run(session{command: "commit hi", login: key, agentKeys: []any{key}})

	if got.status != 1 || !strings.Contains(got.stderr, "None of these SSH keys") || len(h.devnull.commits) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestRefusals(t *testing.T) {
	key := newKey(t)

	cases := []struct {
		name string
		run  session
		want string
	}{
		{"no agent forwarding", session{command: "commit hi", login: key, noForward: true}, "not forwarded"},
		{"empty agent", session{command: "commit hi", login: key}, "holds no Ed25519 or RSA key"},
		{"stdin from a terminal", session{command: "commit", login: key, agentKeys: []any{key}, pty: true}, "pipe it in"},
		{"empty message", session{command: "commit", stdin: " \n", login: key, agentKeys: []any{key}}, "empty commit message"},
		{"bad reply ref", session{command: "commit --reply a;b hi", login: key, agentKeys: []any{key}}, "--reply takes"},
		{"reply twice", session{command: "commit --reply a --reply b hi", login: key, agentKeys: []any{key}}, "only be given once"},
		{"unknown command", session{command: "rm -rf /", login: key, agentKeys: []any{key}}, "ssh -A devnull.test commit"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := startHarness(t)
			got := h.run(c.run)

			if got.status == 0 || !strings.Contains(got.stderr, c.want) {
				t.Fatalf("got %+v, want stderr containing %q", got, c.want)
			}
			if len(h.devnull.commits) != 0 {
				t.Fatal("a commit was sent")
			}
		})
	}
}

func TestPassesOnWhatDevnullRefuses(t *testing.T) {
	h := startHarness(t)
	h.devnull.refuse = "This SSH key is not on the GitHub account of a /dev/null user.\x1b[2J"
	key := newKey(t)

	got := h.run(session{command: "commit hi", login: key, agentKeys: []any{key}})

	if got.status != 1 || !strings.Contains(got.stderr, "not on the GitHub account") || strings.Contains(got.stderr, "\x1b") {
		t.Fatalf("got %+v", got)
	}
}

func TestDashDashKeepsAFlagInTheMessage(t *testing.T) {
	replyTo, message, err := parseCommitArgs(" --  --reply is a flag")
	if err != nil || replyTo != "" || string(message) != "--reply is a flag" {
		t.Fatalf("got %q %q %v", replyTo, message, err)
	}
}

func TestUsageWithoutACommand(t *testing.T) {
	h := startHarness(t)
	key := newKey(t)

	got := h.run(session{command: "help", login: key, agentKeys: []any{key}})

	if got.status != 0 || !strings.Contains(got.stderr, "ForwardAgent yes") {
		t.Fatalf("got %+v", got)
	}
}

func TestUsageShowsThePort(t *testing.T) {
	if got := (config{Name: "example.com", Port: "2222"}).sshCommand(); got != "ssh -A -p 2222 example.com" {
		t.Fatalf("got %q", got)
	}
	if got := (config{Name: "example.com", Port: "22"}).sshCommand(); got != "ssh -A example.com" {
		t.Fatalf("got %q", got)
	}
}
