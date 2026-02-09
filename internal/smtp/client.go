package smtp

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/textproto"
	"sort"
	"strings"
	"time"
)

type Client struct {
	Host               string
	Port               string
	Username           string
	Password           string
	EnvelopeSender     string // Authenticated address for MAIL FROM
	SenderEmail        string // Display From header (spoofed)
	SenderName         string
	InsecureSkipVerify bool
	DKIMDomain         string
	DKIMSelector       string
	DKIMKeyPath        string
}

func NewClient(host, port, username, password, envelopeSender, senderEmail, senderName string, insecureSkipVerify bool, dkimDomain, dkimSelector, dkimKeyPath string) *Client {
	return &Client{
		Host:               host,
		Port:               port,
		Username:           username,
		Password:           password,
		EnvelopeSender:     envelopeSender,
		SenderEmail:        senderEmail,
		SenderName:         senderName,
		InsecureSkipVerify: insecureSkipVerify,
		DKIMDomain:         dkimDomain,
		DKIMSelector:       dkimSelector,
		DKIMKeyPath:        dkimKeyPath,
	}
}

// senderDomain extracts the domain part from an email address.
func senderDomain(email string) string {
	if idx := strings.LastIndex(email, "@"); idx >= 0 {
		return email[idx+1:]
	}
	return "localhost"
}

// Send implements the raw SMTP protocol to inject custom headers.
func (c *Client) Send(to, subject, body string) error {
	address := fmt.Sprintf("%s:%s", c.Host, c.Port)
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer conn.Close()

	tp := textproto.NewConn(conn)

	if _, _, err := tp.ReadResponse(220); err != nil {
		return fmt.Errorf("greeting failed: %w", err)
	}

	sendCommand := func(expectCode int, format string, args ...any) error {
		id, err := tp.Cmd(format, args...)
		if err != nil {
			return err
		}
		tp.StartResponse(id)
		defer tp.EndResponse(id)
		if _, _, err := tp.ReadResponse(expectCode); err != nil {
			return err
		}
		return nil
	}

	domain := senderDomain(c.EnvelopeSender)

	if err := sendCommand(250, "EHLO %s", domain); err != nil {
		return fmt.Errorf("EHLO failed: %w", err)
	}

	// STARTTLS
	if id, err := tp.Cmd("STARTTLS"); err == nil {
		tp.StartResponse(id)
		code, _, err := tp.ReadResponse(220)
		tp.EndResponse(id)

		if err == nil && code == 220 {
			tlsConn := tls.Client(conn, &tls.Config{
				InsecureSkipVerify: c.InsecureSkipVerify,
				ServerName:         c.Host,
			})
			tp = textproto.NewConn(tlsConn)

			if err := sendCommand(250, "EHLO %s", domain); err != nil {
				return fmt.Errorf("post-TLS EHLO failed: %w", err)
			}
		}
	}

	// AUTH  - try LOGIN first (Brevo preference), fall back to PLAIN
	if c.Username != "" && c.Password != "" {
		userB64 := base64.StdEncoding.EncodeToString([]byte(c.Username))
		passB64 := base64.StdEncoding.EncodeToString([]byte(c.Password))

		// AUTH LOGIN: server prompts for username then password
		if err := sendCommand(334, "AUTH LOGIN"); err == nil {
			if err := sendCommand(334, "%s", userB64); err != nil {
				return fmt.Errorf("AUTH LOGIN username rejected: %w", err)
			}
			if err := sendCommand(235, "%s", passB64); err != nil {
				return fmt.Errorf("AUTH LOGIN password rejected: %w", err)
			}
		} else {
			// Fallback: AUTH PLAIN
			plain := base64.StdEncoding.EncodeToString(
				[]byte("\x00" + c.Username + "\x00" + c.Password),
			)
			if err := sendCommand(235, "AUTH PLAIN %s", plain); err != nil {
				return fmt.Errorf("AUTH failed: %w", err)
			}
		}
	}

	// MAIL FROM (envelope sender = Brevo-verified address for relay auth)
	if err := sendCommand(250, "MAIL FROM:<%s>", c.EnvelopeSender); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	if err := sendCommand(250, "RCPT TO:<%s>", to); err != nil {
		return fmt.Errorf("RCPT TO failed: %w", err)
	}

	if err := sendCommand(354, "DATA"); err != nil {
		return fmt.Errorf("DATA failed: %w", err)
	}

	// Manually crafted RFC 5322 headers  - spoofed From + Reply-To
	msg := strings.Join([]string{
		fmt.Sprintf("From: %s <%s>", c.SenderName, c.SenderEmail),
		fmt.Sprintf("Reply-To: %s <%s>", c.SenderName, c.SenderEmail),
		fmt.Sprintf("To: %s", to),
		fmt.Sprintf("Subject: %s", subject),
		fmt.Sprintf("Date: %s", time.Now().Format(time.RFC1123Z)),
		fmt.Sprintf("Message-ID: <%d@%s>", time.Now().UnixNano(), domain),
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=UTF-8",
	}, "\r\n") + "\r\n\r\n" + body

	if c.DKIMDomain != "" && c.DKIMSelector != "" && c.DKIMKeyPath != "" {
		msg, err = SignMessage(msg, c.DKIMDomain, c.DKIMSelector, c.DKIMKeyPath)
		if err != nil {
			return fmt.Errorf("DKIM signing: %w", err)
		}
	}

	w := tp.Writer.W
	if _, err := w.WriteString(msg); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}
	if _, err := w.WriteString("\r\n.\r\n"); err != nil {
		return fmt.Errorf("failed to write terminator: %w", err)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("failed to flush: %w", err)
	}

	if _, _, err := tp.ReadResponse(250); err != nil {
		return fmt.Errorf("message rejected: %w", err)
	}

	_ = sendCommand(221, "QUIT")
	return nil
}

// SendDirect delivers email directly to the recipient's MX server on port 25.
// No relay, no auth, full control over From header  - true spoofing.
func (c *Client) SendDirect(to, subject, body string) error {
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

	var lastErr error
	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		lastErr = c.sendToMX(host, to, subject, body)
		if lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("all MX servers failed, last error: %w", lastErr)
}

func (c *Client) sendToMX(mxHost, to, subject, body string) error {
	conn, err := net.DialTimeout("tcp4", mxHost+":25", 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect to %s:25 failed: %w", mxHost, err)
	}
	defer conn.Close()

	tp := textproto.NewConn(conn)

	if _, _, err := tp.ReadResponse(220); err != nil {
		return fmt.Errorf("greeting from %s failed: %w", mxHost, err)
	}

	sendCommand := func(expectCode int, format string, args ...any) error {
		id, err := tp.Cmd(format, args...)
		if err != nil {
			return err
		}
		tp.StartResponse(id)
		defer tp.EndResponse(id)
		if _, _, err := tp.ReadResponse(expectCode); err != nil {
			return err
		}
		return nil
	}

	domain := senderDomain(c.SenderEmail)

	if err := sendCommand(250, "EHLO %s", domain); err != nil {
		return fmt.Errorf("EHLO failed: %w", err)
	}

	// Opportunistic STARTTLS
	if id, err := tp.Cmd("STARTTLS"); err == nil {
		tp.StartResponse(id)
		code, _, err := tp.ReadResponse(220)
		tp.EndResponse(id)

		if err == nil && code == 220 {
			tlsConn := tls.Client(conn, &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         mxHost,
			})
			tp = textproto.NewConn(tlsConn)

			if err := sendCommand(250, "EHLO %s", domain); err != nil {
				return fmt.Errorf("post-TLS EHLO failed: %w", err)
			}
		}
	}

	// No AUTH  - direct delivery

	if err := sendCommand(250, "MAIL FROM:<%s>", c.SenderEmail); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	if err := sendCommand(250, "RCPT TO:<%s>", to); err != nil {
		return fmt.Errorf("RCPT TO failed: %w", err)
	}

	if err := sendCommand(354, "DATA"); err != nil {
		return fmt.Errorf("DATA failed: %w", err)
	}

	msg := strings.Join([]string{
		fmt.Sprintf("From: %s <%s>", c.SenderName, c.SenderEmail),
		fmt.Sprintf("Reply-To: %s <%s>", c.SenderName, c.SenderEmail),
		fmt.Sprintf("To: %s", to),
		fmt.Sprintf("Subject: %s", subject),
		fmt.Sprintf("Date: %s", time.Now().Format(time.RFC1123Z)),
		fmt.Sprintf("Message-ID: <%d@%s>", time.Now().UnixNano(), domain),
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=UTF-8",
	}, "\r\n") + "\r\n\r\n" + body

	if c.DKIMDomain != "" && c.DKIMSelector != "" && c.DKIMKeyPath != "" {
		msg, err = SignMessage(msg, c.DKIMDomain, c.DKIMSelector, c.DKIMKeyPath)
		if err != nil {
			return fmt.Errorf("DKIM signing: %w", err)
		}
	}

	w := tp.Writer.W
	if _, err := w.WriteString(msg); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}
	if _, err := w.WriteString("\r\n.\r\n"); err != nil {
		return fmt.Errorf("failed to write terminator: %w", err)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("failed to flush: %w", err)
	}

	if _, _, err := tp.ReadResponse(250); err != nil {
		return fmt.Errorf("message rejected by %s: %w", mxHost, err)
	}

	_ = sendCommand(221, "QUIT")
	return nil
}
