package main

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"phishing-simulator/config"
	"phishing-simulator/internal/smtp"
)

//go:embed web/templates/*.html
var templateFS embed.FS

type PageData struct {
	Success string
	Error   string
}

type EmailData struct {
	Subject     string
	Body        template.HTML
	TrackingURL string
	SenderName  string
	SenderEmail string
	ImageURL    string
}

type PhishedData struct {
	IP        string
	UserAgent string
	Timestamp string
	Recipient string
}

func main() {
	cfg := config.Load()

	tmpl, err := template.ParseFS(templateFS, "web/templates/form.html")
	if err != nil {
		log.Fatalf("Failed to parse form template: %v", err)
	}

	emailTmpl, err := template.ParseFS(templateFS, "web/templates/email.html")
	if err != nil {
		log.Fatalf("Failed to parse email template: %v", err)
	}

	phishedTmpl, err := template.ParseFS(templateFS, "web/templates/phished.html")
	if err != nil {
		log.Fatalf("Failed to parse phished template: %v", err)
	}

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tmpl.Execute(w, nil)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Click tracking endpoint  - logs visitor data, redirects to /phished
	http.HandleFunc("/click", func(w http.ResponseWriter, r *http.Request) {
		recipient := r.URL.Query().Get("id")
		ip := r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip = r.RemoteAddr
		}
		ua := r.Header.Get("User-Agent")

		log.Printf("[CLICK] recipient=%s ip=%s ua=%s time=%s",
			recipient, ip, ua, time.Now().Format(time.RFC3339))

		http.Redirect(w, r, "/phished?id="+url.QueryEscape(recipient)+"&ip="+url.QueryEscape(ip), http.StatusFound)
	})

	// Phished landing page  - reveals the test
	http.HandleFunc("/phished", func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			ip = r.Header.Get("X-Forwarded-For")
			if ip == "" {
				ip = r.RemoteAddr
			}
		}
		data := PhishedData{
			IP:        ip,
			UserAgent: r.Header.Get("User-Agent"),
			Timestamp: time.Now().Format("Jan 02, 2006 at 15:04:05 MST"),
			Recipient: r.URL.Query().Get("id"),
		}
		phishedTmpl.Execute(w, data)
	})

	http.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		to := r.FormValue("to")
		subject := r.FormValue("subject")
		body := r.FormValue("body")

		if to == "" || subject == "" || len(strings.TrimSpace(body)) == 0 {
			tmpl.Execute(w, PageData{Error: "All fields are required (body must not be empty)."})
			return
		}

		emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
		matched, _ := regexp.MatchString(emailRegex, to)
		if !matched {
			tmpl.Execute(w, PageData{Error: "Invalid recipient email format (must be user@domain.tld)."})
			return
		}

		if len(body) > 1000 {
			tmpl.Execute(w, PageData{Error: fmt.Sprintf("Body too long! Limit is 1000 characters (current: %d).", len(body))})
			return
		}

		if strings.ContainsAny(to, "\r\n") || strings.ContainsAny(subject, "\r\n") {
			tmpl.Execute(w, PageData{Error: "Invalid input detected."})
			return
		}

		// Build tracking URL from BASE_URL or fall back to request host
		baseURL := cfg.BaseURL
		if baseURL == "" {
			baseURL = "http://" + r.Host
		}
		trackingURL := fmt.Sprintf("%s/click?id=%s", strings.TrimRight(baseURL, "/"), url.QueryEscape(to))

		// Render HTML email from template
		htmlBody := strings.ReplaceAll(body, "\n", "<br/>")
		emailData := EmailData{
			Subject:     subject,
			Body:        template.HTML(htmlBody),
			TrackingURL: trackingURL,
			SenderName:  cfg.SMTPSenderName,
			SenderEmail: cfg.SMTPSenderEmail,
			ImageURL:    "https://0x0.st/PAsv.jpeg",
		}
		var buf bytes.Buffer
		if err := emailTmpl.Execute(&buf, emailData); err != nil {
			tmpl.Execute(w, PageData{Error: fmt.Sprintf("Failed to render email: %v", err)})
			return
		}

		dkimDomain := cfg.DKIMDomain
		dkimSelector := cfg.DKIMSelector
		dkimKeyPath := cfg.DKIMPrivateKeyPath
		if !cfg.DKIMEnabled {
			dkimDomain = ""
			dkimSelector = ""
			dkimKeyPath = ""
		}

		client := smtp.NewClient(
			cfg.SMTPHost,
			cfg.SMTPPort,
			cfg.SMTPSenderUser,
			cfg.SMTPSenderPass,
			cfg.SMTPEnvelopeSender,
			cfg.SMTPSenderEmail,
			cfg.SMTPSenderName,
			cfg.InsecureSkipVerify,
			dkimDomain,
			dkimSelector,
			dkimKeyPath,
		)

		var sendErr error
		if cfg.SMTPMode == "direct" {
			envelopeSender := to // match-recipient: use recipient address as envelope sender
			if cfg.EnvelopeStrategy == "custom" {
				envelopeSender = cfg.SMTPEnvelopeSender
			}
			sendErr = smtp.SendViaSwaks(cfg.PerlPath, cfg.SwaksPath, to, envelopeSender, cfg.SMTPSenderEmail, cfg.SMTPSenderName, subject, buf.String(), dkimDomain, dkimSelector, dkimKeyPath)
		} else {
			sendErr = client.Send(to, subject, buf.String())
		}
		if sendErr != nil {
			log.Printf("Error sending email: %v", sendErr)
			tmpl.Execute(w, PageData{Error: fmt.Sprintf("Failed to send email: %v", sendErr)})
			return
		}

		log.Printf("Email sent to %s (mode=%s)", to, cfg.SMTPMode)
		tmpl.Execute(w, PageData{Success: "Email successfully spoofed and sent!"})
	})

	log.Printf("Server listening on port %s", cfg.Port)
	log.Printf("Configuration: Mode=%s, From=%s <%s>",
		cfg.SMTPMode, cfg.SMTPSenderName, cfg.SMTPSenderEmail)

	if err := http.ListenAndServe(":"+cfg.Port, nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
