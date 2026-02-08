package main

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strings"

	"phishing-simulator/config"
	"phishing-simulator/internal/smtp"
)

//go:embed web/templates/*.html
var templateFS embed.FS

type PageData struct {
	Success string
	Error   string
}

func main() {
	cfg := config.Load()

	// Parse templates
	tmpl, err := template.ParseFS(templateFS, "web/templates/form.html")
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tmpl.Execute(w, nil)
	})

	http.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		to := r.FormValue("to")
		subject := r.FormValue("subject")
		body := r.FormValue("body")

		// Basic Validation: All fields required, body must not be empty
		if to == "" || subject == "" || len(strings.TrimSpace(body)) == 0 {
			tmpl.Execute(w, PageData{Error: "All fields are required (body must not be empty)."})
			return
		}

		// Validation 1: Strict Email Regex (must have dot)
		// Regex: ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$
		emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
		matched, _ := regexp.MatchString(emailRegex, to)
		if !matched {
			tmpl.Execute(w, PageData{Error: "Invalid recipient email format (must be user@domain.tld)."})
			return
		}

		// Validation 2: Character Count Limit (Max 1000 chars)
		if len(body) > 1000 {
			tmpl.Execute(w, PageData{Error: fmt.Sprintf("Body too long! Limit is 1000 characters (current: %d).", len(body))})
			return
		}

		// Security: Prevent Header Injection via Form
		// We are manually crafting headers, so we simply ensure no newlines in subject/to
		if strings.ContainsAny(to, "\r\n") || strings.ContainsAny(subject, "\r\n") {
			tmpl.Execute(w, PageData{Error: "Invalid input detected."})
			return
		}

		client := smtp.NewClient(
			cfg.SMTPHost,
			cfg.SMTPPort,
			cfg.SMTPSenderUser,
			cfg.SMTPSenderPass,
			cfg.SMTPSenderEmail,
			cfg.SMTPSenderName,
			cfg.InsecureSkipVerify,
			cfg.DirectMode,
		)

		err := client.Send(to, subject, body)
		if err != nil {
			log.Printf("Error sending email: %v", err)
			tmpl.Execute(w, PageData{Error: fmt.Sprintf("Failed to send email: %v", err)})
			return
		}

		log.Printf("Email sent to %s via %s:%s", to, cfg.SMTPHost, cfg.SMTPPort)
		tmpl.Execute(w, PageData{Success: "Email successfully spoofed and sent!"})
	})

	log.Printf("Server listening on port %s", cfg.Port)
	log.Printf("Configuration: SMTP Host=%s, Port=%s, Sender=%s <%s>, DirectMode=%v",
		cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPSenderName, cfg.SMTPSenderEmail, cfg.DirectMode)

	if err := http.ListenAndServe(":"+cfg.Port, nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
