package main

import (
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// The SSHSIG format, as made by `ssh-keygen -Y sign`:
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
const (
	sshsigMagic   = "SSHSIG"
	sshsigVersion = 1
	sshsigHash    = "sha512"
)

// signedData is what the key actually signs: the namespace and the hash of the message, never the message itself, so
// a signature made for one namespace can't be passed off as one for another.
func signedData(namespace string, message []byte) []byte {
	hash := sha512.Sum512(message)

	return append([]byte(sshsigMagic), gossh.Marshal(struct {
		Namespace     string
		Reserved      string
		HashAlgorithm string
		Hash          string
	}{namespace, "", sshsigHash, string(hash[:])})...)
}

// signSSHSIG has the agent sign the message with the key, and returns the signature as the single line of base64 that
// `ssh-keygen -Y sign` puts between its armor lines.
func signSSHSIG(keyring agentSigner, key gossh.PublicKey, namespace string, message []byte) (string, error) {
	var flags agent.SignatureFlags
	if key.Type() == gossh.KeyAlgoRSA {
		// ssh-keygen signs with rsa-sha2-512, never the SHA-1 "ssh-rsa" signature that dev-null.sh refuses.
		flags = agent.SignatureFlagRsaSha512
	}

	data := signedData(namespace, message)
	signature, err := keyring.SignWithFlags(key, data, flags)
	if err != nil {
		return "", errors.New("Your SSH agent did not sign the commit.")
	}

	// Checked here, so a bad signature gets a reason instead of dev-null.sh's bare "Invalid signature.".
	if key.Type() == gossh.KeyAlgoRSA && signature.Format != gossh.KeyAlgoRSASHA512 {
		return "", fmt.Errorf("Your SSH agent signed with %s, not rsa-sha2-512, which dev-null.sh needs. Try an Ed25519 key or a newer agent.", signature.Format)
	}
	if key.Verify(data, signature) != nil {
		return "", errors.New("Your SSH agent made a signature that does not check out.")
	}

	blob := append([]byte(sshsigMagic), gossh.Marshal(struct {
		Version       uint32
		PublicKey     string
		Namespace     string
		Reserved      string
		HashAlgorithm string
		Signature     string
	}{sshsigVersion, string(key.Marshal()), namespace, "", sshsigHash, string(gossh.Marshal(signature))})...)

	return base64.StdEncoding.EncodeToString(blob), nil
}
