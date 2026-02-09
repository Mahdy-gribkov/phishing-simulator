package smtp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
)

// SignMessage adds a DKIM-Signature header to an RFC 5322 message.
// It reads the private key from keyPath, signs with relaxed/relaxed
// canonicalization, and returns the signed message string.
func SignMessage(msg, domain, selector, keyPath string) (string, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("reading DKIM key %s: %w", keyPath, err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return "", fmt.Errorf("no PEM block found in %s", keyPath)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Fall back to PKCS1 format
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("parsing DKIM private key: %w", err)
		}
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return "", fmt.Errorf("DKIM key does not implement crypto.Signer")
	}

	opts := &dkim.SignOptions{
		Domain:   domain,
		Selector: selector,
		Signer:   signer,
		HeaderKeys: []string{
			"From", "To", "Subject", "Date",
			"Message-ID", "MIME-Version", "Content-Type",
		},
	}

	var signed bytes.Buffer
	if err := dkim.Sign(&signed, strings.NewReader(msg), opts); err != nil {
		return "", fmt.Errorf("DKIM signing: %w", err)
	}

	return signed.String(), nil
}
