package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// The namespace dev-null.sh verifies commit signatures under (commits with images use another one).
const commitNamespace = "devnull-commit"

// maxResponseBytes caps what is read of dev-null.sh's answer, which is a short line of text.
const maxResponseBytes = 64 << 10

// commitPayload is what gets signed and sent: "<unix timestamp>\n<nonce>\n<commit to reply to, or empty>\n<body>",
// as the official commit script builds it.
func commitPayload(now time.Time, replyTo, body string) ([]byte, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return []byte(strconv.FormatInt(now.Unix(), 10) + "\n" + hex.EncodeToString(nonce) + "\n" + replyTo + "\n" + body), nil
}

// validReplyTo matches what the commit script lets on the reply line: the hash of a commit, or its link.
func validReplyTo(ref string) bool {
	if ref == "" {
		return false
	}

	for _, r := range ref {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(":/._@-", r)
		if !ok {
			return false
		}
	}

	return true
}

// checkBaseURL allows https, and plain http only to this machine, like the commit script.
func checkBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}

	host := u.Hostname()
	if u.Scheme == "https" || u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1") {
		return nil
	}

	return fmt.Errorf("DEVNULL_URL must be an https:// URL, not %q", raw)
}

// newHTTPClient never follows redirects, so a commit only ever goes to DEVNULL_URL.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// lookupKey asks dev-null.sh which of the keys is on the GitHub account of a user, like the commit script. Only one of
// the keys asked about is ever returned, whatever dev-null.sh answers.
func lookupKey(ctx context.Context, client *http.Client, baseURL string, keys []gossh.PublicKey) (gossh.PublicKey, error) {
	var body strings.Builder
	for _, key := range keys {
		body.WriteString(key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal()) + "\n")
	}

	answer, err := post(ctx, client, baseURL, "/api/cli/key-lookups", []byte(body.String()), nil)
	if err != nil {
		return nil, err
	}

	firstLine, _, _ := strings.Cut(answer, "\n")
	found, _, _, _, err := gossh.ParseAuthorizedKey([]byte(firstLine))
	if err == nil {
		for _, key := range keys {
			if bytes.Equal(found.Marshal(), key.Marshal()) {
				return key, nil
			}
		}
	}

	return nil, fmt.Errorf("Unexpected answer from %s.", baseURL)
}

// postCommit sends the signed commit, and returns dev-null.sh's answer, which is plain text either way.
func postCommit(ctx context.Context, client *http.Client, baseURL string, payload []byte, signature string) (string, error) {
	return post(ctx, client, baseURL, "/api/cli/commits", payload, map[string]string{"X-SSH-Signature": signature})
}

// post sends text to dev-null.sh, and returns its answer, which is plain text whether it succeeded or not.
func post(ctx context.Context, client *http.Client, baseURL, path string, body []byte, headers map[string]string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return "", err
	}

	request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	for name, value := range headers {
		request.Header.Set(name, value)
	}

	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("could not reach %s", baseURL)
	}
	defer response.Body.Close()

	answer, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("could not read the answer of %s", baseURL)
	}

	text := sanitize(strings.TrimSpace(string(answer)))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if text == "" {
			text = fmt.Sprintf("Unexpected answer from %s (HTTP %d).", baseURL, response.StatusCode)
		}

		return "", errors.New(text)
	}

	return text, nil
}

// sanitize drops control characters (such as terminal escape sequences) from text sent back to the user, except
// newlines and tabs.
func sanitize(text string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 0x20 && r != 0x7f && (r < 0x80 || r > 0x9f) {
			return r
		}

		return -1
	}, text)
}
