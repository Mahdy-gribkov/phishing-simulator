package smtp

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"time"
)

type Client struct {
	Host               string
	Port               string
	Username           string
	Password           string
	SenderEmail        string // The "From" address to spoof (e.g. donald@trump.com)
	InsecureSkipVerify bool
}

func NewClient(host, port, username, password, senderEmail string, insecureSkipVerify bool) *Client {
	return &Client{
		Host:               host,
		Port:               port,
		Username:           username,
		Password:           password,
		SenderEmail:        senderEmail,
		InsecureSkipVerify: insecureSkipVerify,
	}
}

// Send implements the raw SMTP protocol to inject custom headers
func (c *Client) Send(to, subject, body string) error {
	address := fmt.Sprintf("%s:%s", c.Host, c.Port)
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer conn.Close()

	tp := textproto.NewConn(conn)

	// 1. Read greeting
	if _, _, err := tp.ReadResponse(220); err != nil {
		return fmt.Errorf("greeting failed: %w", err)
	}

	// Helper to send command and check response
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

	// 2. EHLO
	if err := sendCommand(250, "EHLO localhost"); err != nil {
		return fmt.Errorf("EHLO failed: %w", err)
	}

	// 3. STARTTLS
	if id, err := tp.Cmd("STARTTLS"); err == nil {
		tp.StartResponse(id)
		code, _, err := tp.ReadResponse(220)
		tp.EndResponse(id)

		if err == nil && code == 220 {
			// Handshake
			tlsConfig := &tls.Config{
				InsecureSkipVerify: c.InsecureSkipVerify,
				ServerName:         c.Host,
			}
			tlsConn := tls.Client(conn, tlsConfig)
			tp = textproto.NewConn(tlsConn)

			// Re-EHLO
			if err := sendCommand(250, "EHLO localhost"); err != nil {
				return fmt.Errorf("post-TLS EHLO failed: %w", err)
			}
		}
	}

	// 3.5 AUTH PLAIN (If configured)
	if c.Username != "" && c.Password != "" {
		identity := ""
		auth := []byte(identity + "\x00" + c.Username + "\x00" + c.Password)
		authStr := base64.StdEncoding.EncodeToString(auth)

		if err := sendCommand(235, "AUTH PLAIN %s", authStr); err != nil {
			return fmt.Errorf("AUTH PLAIN failed: %w", err)
		}
	}

	// 4. MAIL FROM
	if err := sendCommand(250, "MAIL FROM:<%s>", c.Username); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	// 5. RCPT TO
	if err := sendCommand(250, "RCPT TO:<%s>", to); err != nil {
		return fmt.Errorf("RCPT TO failed: %w", err)
	}

	// 6. DATA
	if err := sendCommand(354, "DATA"); err != nil {
		return fmt.Errorf("DATA failed: %w", err)
	}

	// 7. Inject Headers & Body
	headers := []string{
		fmt.Sprintf("From: Donald Trump <%s>", c.SenderEmail), // The spoofed sender
		fmt.Sprintf("To: %s", to),
		fmt.Sprintf("Subject: %s", subject),
		fmt.Sprintf("Date: %s", time.Now().Format(time.RFC1123Z)),
		fmt.Sprintf("Message-ID: <%d@whitehouse.gov>", time.Now().UnixNano()),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
	}

	msg := strings.Join(headers, "\r\n") + "\r\n\r\n" + body + "\r\n."

	// Send message content
	w := tp.Writer.W
	if _, err := w.WriteString(msg); err != nil {
		return fmt.Errorf("failed to write body: %w", err)
	}
	if _, err := w.WriteString("\r\n"); err != nil {
		return fmt.Errorf("failed to write terminator: %w", err)
	}

	if err := w.Flush(); err != nil {
		return fmt.Errorf("failed to flush body: %w", err)
	}

	// 8. Wait for DATA confirmation
	if _, _, err := tp.ReadResponse(250); err != nil {
		return fmt.Errorf("message data confirmation failed: %w", err)
	}

	// 9. QUIT
	_ = sendCommand(221, "QUIT")

	return nil
}
