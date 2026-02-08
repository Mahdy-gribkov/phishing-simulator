package main

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
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

		// Basic Validation
		if to == "" || subject == "" || body == "" {
			tmpl.Execute(w, PageData{Error: "All fields are required."})
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
			cfg.InsecureSkipVerify,
		)

		err := client.Send(to, subject, body)
		if err != nil {
			log.Printf("Error sending email: %v", err)
			tmpl.Execute(w, PageData{Error: fmt.Sprintf("Failed to send email: %v", err)})
			return
		}

		log.Printf("Email sent to %s via %s:%s", to, cfg.SMTPHost, cfg.SMTPPort)
		tmpl.Execute(w, PageData{Success: "Email successfully spoofed and sent (check MailHog)!"})
	})

	log.Printf("Server listening on port %s", cfg.Port)
	log.Printf("Configuration: SMTP Host=%s, Port=%s, Sender=%s", cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPSenderEmail)

	if err := http.ListenAndServe(":"+cfg.Port, nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
