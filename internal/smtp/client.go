package smtp

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"strings"
	"time"
)

type Client struct {
	Host               string
	Port               string
	Username           string
	Password           string
	SenderEmail        string
	SenderName         string
	InsecureSkipVerify bool
	DirectMode         bool
}

func NewClient(host, port, username, password, senderEmail, senderName string, insecureSkipVerify, directMode bool) *Client {
	return &Client{
		Host:               host,
		Port:               port,
		Username:           username,
		Password:           password,
		SenderEmail:        senderEmail,
		SenderName:         senderName,
		InsecureSkipVerify: insecureSkipVerify,
		DirectMode:         directMode,
	}
}

func (c *Client) Send(to, subject, body string) error {
	var targetHost, targetPort string
	targetHost = c.Host
	targetPort = c.Port

	// --- DIRECT DELIVERY LOGIC ---
	if c.DirectMode {
		parts := strings.Split(to, "@")
		if len(parts) != 2 {
			return fmt.Errorf("invalid recipient email: %s", to)
		}
		domain := parts[1]

		mxs, err := net.LookupMX(domain)
		if err != nil {
			return fmt.Errorf("MX lookup failed for %s: %v", domain, err)
		}
		if len(mxs) == 0 {
			return fmt.Errorf("no MX records found for %s", domain)
		}
		targetHost = mxs[0].Host
		targetPort = "25"
		log.Printf("[DirectMode] Targeting MX for %s: %s:%s", domain, targetHost, targetPort)
	}
	// -----------------------------

	addr := fmt.Sprintf("%s:%s", targetHost, targetPort)

	// 1. Connect
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server %s: %w", addr, err)
	}

	// 2. Wrap via Standard Library Client
	client, err := smtp.NewClient(conn, targetHost)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Quit()

	// 3. Hello
	if err = client.Hello("localhost"); err != nil {
		return fmt.Errorf("HELO failed: %w", err)
	}

	// 4. STARTTLS
	if ok, _ := client.Extension("STARTTLS"); ok {
		config := &tls.Config{
			InsecureSkipVerify: c.InsecureSkipVerify,
			ServerName:         targetHost,
		}
		if err = client.StartTLS(config); err != nil {
			// In Direct Mode, failure might be acceptable, but usually we want to know
			log.Printf("STARTTLS warning: %v", err)
		}
	}

	// 5. Auth (Standard Library handles PLAIN/LOGIN/CRAM-MD5 automatically)
	if !c.DirectMode && c.Username != "" && c.Password != "" {
		auth := smtp.PlainAuth("", c.Username, c.Password, c.Host)
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
	}

	// 6. Mail Transaction
	if err = client.Mail(c.SenderEmail); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}
	if err = client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO failed: %w", err)
	}

	// 7. Data
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed: %w", err)
	}
	// Do not defer w.Close() here - we need to check the error!

	// Headers
	// Note: We need a unique Message-ID to avoid "Header parsing error" or spam blocks
	domain := "localhost"
	if strings.Contains(c.SenderEmail, "@") {
		domain = strings.Split(c.SenderEmail, "@")[1]
	}
	msgID := fmt.Sprintf("<%d.%s@%s>", time.Now().UnixNano(), "phishing-sim", domain)

	headers := []string{
		fmt.Sprintf("From: %s <%s>", c.SenderName, c.SenderEmail),
		fmt.Sprintf("To: %s", to),
		fmt.Sprintf("Subject: %s", subject),
		fmt.Sprintf("Date: %s", time.Now().Format(time.RFC1123Z)),
		fmt.Sprintf("Message-ID: %s", msgID),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
	}

	// SMTP requires standard Network Newlines (\r\n)
	// We join headers with \r\n, and then add TWO \r\n before the body.
	msg := strings.Join(headers, "\r\n") + "\r\n\r\n" + body

	if _, err = w.Write([]byte(msg)); err != nil {
		w.Close() // Close anyway to clean up
		return fmt.Errorf("failed to write body: %w", err)
	}

	// MUST explicitly close to send the "." and check the server's response code (250 OK)
	if err = w.Close(); err != nil {
		return fmt.Errorf("message rejected by server: %w", err)
	}

	return nil
}
