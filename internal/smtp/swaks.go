package smtp

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

)

// knownPerlPaths lists Perl installations to try when PERL_PATH is not set.
var knownPerlPaths = []string{
	`C:\Ruby34-x64\msys64\usr\bin\perl.exe`,
	`C:\Strawberry\perl\bin\perl.exe`,
}

// findPerl resolves the Perl binary path. If perlPath is set, it uses that directly.
// Otherwise it checks known Windows locations, then falls back to PATH lookup.
func findPerl(perlPath string) (string, error) {
	if perlPath != "" {
		if _, err := os.Stat(perlPath); err == nil {
			return perlPath, nil
		}
		return "", fmt.Errorf("configured PERL_PATH not found: %s", perlPath)
	}

	for _, p := range knownPerlPaths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	if p, err := exec.LookPath("perl"); err == nil {
		return p, nil
	}

	return "", fmt.Errorf("perl not found: set PERL_PATH or install Strawberry Perl")
}

// resolveSwaksPath resolves the swaks.pl path relative to the running executable
// if it's not an absolute path.
func resolveSwaksPath(swaksPath string) string {
	if filepath.IsAbs(swaksPath) {
		return swaksPath
	}
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), swaksPath)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	// Try relative to working directory
	if abs, err := filepath.Abs(swaksPath); err == nil {
		return abs
	}
	return swaksPath
}

// SendViaSwaks sends an email by shelling out to swaks.pl via Perl.
// It performs MX lookup, builds a full RFC822 message, and pipes it to swaks
// via stdin (--data -) to avoid file path and shell escaping issues.
func SendViaSwaks(perlPath, swaksPath, to, envelopeSender, displayFrom, displayName, subject, body string) error {
	perl, err := findPerl(perlPath)
	if err != nil {
		return err
	}

	swaks := resolveSwaksPath(swaksPath)
	if _, err := os.Stat(swaks); err != nil {
		return fmt.Errorf("swaks.pl not found at %s", swaks)
	}

	// MX lookup
	recipientDomain := senderDomain(to)
	mxRecords, err := net.LookupMX(recipientDomain)
	if err != nil {
		return fmt.Errorf("MX lookup failed for %s: %w", recipientDomain, err)
	}
	if len(mxRecords) == 0 {
		return fmt.Errorf("no MX records found for %s", recipientDomain)
	}

	sort.Slice(mxRecords, func(i, j int) bool {
		return mxRecords[i].Pref < mxRecords[j].Pref
	})

	mxHost := strings.TrimSuffix(mxRecords[0].Host, ".")
	hFrom := fmt.Sprintf("%s <%s>", displayName, displayFrom)
	domain := senderDomain(displayFrom)

	// Build full RFC822 message to pipe via stdin
	msg := fmt.Sprintf("From: %s\r\nReply-To: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%d@%s>\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		hFrom, hFrom, to, subject,
		time.Now().Format(time.RFC1123Z),
		time.Now().UnixNano(), domain,
		body,
	)

	args := []string{
		swaks,
		"--to", to,
		"--from", envelopeSender,
		"--data", "-",
		"--server", mxHost,
		"--port", "25",
		"--timeout", "30",
	}

	log.Printf("[swaks] Sending to %s via MX %s (envelope: %s, display: %s)", to, mxHost, envelopeSender, hFrom)

	cmd := exec.Command(perl, args...)
	cmd.Stdin = strings.NewReader(msg)
	output, err := cmd.CombinedOutput()

	log.Printf("[swaks] Output:\n%s", string(output))

	if err != nil {
		return fmt.Errorf("swaks failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}
