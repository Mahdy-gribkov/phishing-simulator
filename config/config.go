package config

import (
	"os"
)

type Config struct {
	Port               string
	SMTPMode           string // "relay" (default), "direct", or "open-relay"
	SMTPHost           string
	SMTPPort           string
	SMTPEnvelopeSender string // Authenticated relay address (MAIL FROM)
	SMTPSenderEmail    string // Display From header (can be spoofed)
	SMTPSenderName     string // Display name in From header
	SMTPSenderUser     string // For AUTH
	SMTPSenderPass     string // For AUTH
	InsecureSkipVerify bool
	PerlPath           string // Path to perl binary (auto-detected if empty)
	SwaksPath          string // Path to swaks.pl script
	EnvelopeStrategy   string // "match-recipient" or "custom"
}

func Load() *Config {
	senderEmail := getEnv("SMTP_SENDER_EMAIL", "president@whitehouse.gov")
	return &Config{
		Port:               getEnv("PORT", "8080"),
		SMTPMode:           getEnv("SMTP_MODE", "relay"),
		SMTPHost:           getEnv("SMTP_HOST", "localhost"),
		SMTPPort:           getEnv("SMTP_PORT", "1025"),
		SMTPEnvelopeSender: getEnv("SMTP_ENVELOPE_SENDER", senderEmail),
		SMTPSenderEmail:    senderEmail,
		SMTPSenderName:     getEnv("SMTP_SENDER_NAME", "Donald Trump"),
		SMTPSenderUser:     getEnv("SMTP_USER", ""),
		SMTPSenderPass:     getEnv("SMTP_PASS", ""),
		InsecureSkipVerify: getEnv("INSECURE_SKIP_VERIFY", "true") == "true",
		PerlPath:           getEnv("PERL_PATH", ""),
		SwaksPath:          getEnv("SWAKS_PATH", "swaks.pl"),
		EnvelopeStrategy:   getEnv("ENVELOPE_STRATEGY", "match-recipient"),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
