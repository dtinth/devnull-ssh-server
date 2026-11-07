package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// verifySSHSIG checks a signature the way dev-null.sh does (app/Dto/SshSignature.php), and returns the key that made
// it.
func verifySSHSIG(message []byte, signature, namespace string) (gossh.PublicKey, error) {
	blob, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || !bytes.HasPrefix(blob, []byte(sshsigMagic)) {
		return nil, errors.New("malformed signature")
	}

	var parsed struct {
		Version       uint32
		PublicKey     string
		Namespace     string
		Reserved      string
		HashAlgorithm string
		Signature     string
	}
	if err := gossh.Unmarshal(blob[len(sshsigMagic):], &parsed); err != nil {
		return nil, err
	}
	if parsed.Version != 1 || parsed.Namespace != namespace || parsed.HashAlgorithm != "sha512" {
		return nil, errors.New("wrong version, namespace or hash")
	}

	key, err := gossh.ParsePublicKey([]byte(parsed.PublicKey))
	if err != nil {
		return nil, err
	}

	var sig gossh.Signature
	if err := gossh.Unmarshal([]byte(parsed.Signature), &sig); err != nil {
		return nil, err
	}
	if sig.Format == gossh.KeyAlgoRSA {
		return nil, errors.New("SHA-1 RSA signature")
	}

	return key, key.Verify(signedData(namespace, message), &sig)
}

type testKey struct {
	name    string
	private any
}

func testKeys(t *testing.T) []testKey {
	t.Helper()

	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	return []testKey{{"ed25519", ed}, {"rsa", rsaKey}}
}

func keyringWith(t *testing.T, private any) (agent.ExtendedAgent, gossh.PublicKey) {
	t.Helper()

	keyring := agent.NewKeyring().(agent.ExtendedAgent)
	if err := keyring.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}

	signer, err := gossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}

	return keyring, signer.PublicKey()
}

func TestSignSSHSIGVerifiesLikeDevnull(t *testing.T) {
	for _, k := range testKeys(t) {
		t.Run(k.name, func(t *testing.T) {
			keyring, public := keyringWith(t, k.private)
			message := []byte("1700000000\n00112233445566778899aabbccddeeff\n\nHello world!")

			signature, err := signSSHSIG(keyring, public, commitNamespace, message)
			if err != nil {
				t.Fatal(err)
			}

			key, err := verifySSHSIG(message, signature, commitNamespace)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(key.Marshal(), public.Marshal()) {
				t.Fatal("the signature names another key")
			}

			if _, err := verifySSHSIG(message, signature, "git"); err == nil {
				t.Fatal("the signature passed under another namespace")
			}
			if _, err := verifySSHSIG(append(message, '!'), signature, commitNamespace); err == nil {
				t.Fatal("the signature passed for another message")
			}
		})
	}
}

// OpenSSH's own verifier must accept the signature too, since it defines the format.
func TestSignSSHSIGVerifiesWithSSHKeygen(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}

	for _, k := range testKeys(t) {
		t.Run(k.name, func(t *testing.T) {
			keyring, public := keyringWith(t, k.private)
			message := []byte("1700000000\n00112233445566778899aabbccddeeff\n0be0130\nAgreed!")

			signature, err := signSSHSIG(keyring, public, commitNamespace, message)
			if err != nil {
				t.Fatal(err)
			}

			sigPath := filepath.Join(t.TempDir(), "commit.sig")
			armored := "-----BEGIN SSH SIGNATURE-----\n" + wrap(signature, 70) + "-----END SSH SIGNATURE-----\n"
			if err := os.WriteFile(sigPath, []byte(armored), 0o600); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command("ssh-keygen", "-Y", "check-novalidate", "-n", commitNamespace, "-s", sigPath)
			cmd.Stdin = bytes.NewReader(message)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("ssh-keygen refused the signature: %v\n%s", err, output)
			}
		})
	}
}

// sha1Agent ignores the flag asking for rsa-sha2-512, like some old agents do.
type sha1Agent struct{ signer gossh.Signer }

func (a sha1Agent) SignWithFlags(_ gossh.PublicKey, data []byte, _ agent.SignatureFlags) (*gossh.Signature, error) {
	return a.signer.(gossh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, data, gossh.KeyAlgoRSA)
}

func TestSignSSHSIGRefusesASHA1RSASignature(t *testing.T) {
	rsaKey := testKeys(t)[1].private
	signer, err := gossh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}

	_, err = signSSHSIG(sha1Agent{signer}, signer.PublicKey(), commitNamespace, []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "rsa-sha2-512") {
		t.Fatalf("got %v", err)
	}
}

// wrongKeyAgent signs with another key than the one asked for.
type wrongKeyAgent struct{ signer gossh.Signer }

func (a wrongKeyAgent) SignWithFlags(_ gossh.PublicKey, data []byte, _ agent.SignatureFlags) (*gossh.Signature, error) {
	return a.signer.Sign(rand.Reader, data)
}

func TestSignSSHSIGRefusesASignatureThatDoesNotCheckOut(t *testing.T) {
	keys := testKeys(t)
	_, asked := keyringWith(t, keys[0].private)
	other, err := gossh.NewSignerFromKey(ed25519PrivateKey(t))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := signSSHSIG(wrongKeyAgent{other}, asked, commitNamespace, []byte("x")); err == nil {
		t.Fatal("a signature by another key passed")
	}
}

func ed25519PrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func wrap(text string, width int) string {
	var b strings.Builder
	for len(text) > width {
		b.WriteString(text[:width] + "\n")
		text = text[width:]
	}
	b.WriteString(text + "\n")

	return b.String()
}
