package config

import (
	"os"
)

type Config struct {
	Port               string
	SMTPHost           string
	SMTPPort           string
	SMTPSenderEmail    string
	SMTPSenderName     string // New: Configurable Sender Name
	SMTPSenderUser     string // For AUTH
	SMTPSenderPass     string // For AUTH
	InsecureSkipVerify bool
	DirectMode         bool // New: Bypass Relay, send direct to MX
}

func Load() *Config {
	return &Config{
		Port:               getEnv("PORT", "8080"),
		SMTPHost:           getEnv("SMTP_HOST", "localhost"),
		SMTPPort:           getEnv("SMTP_PORT", "1025"),
		SMTPSenderEmail:    getEnv("SMTP_SENDER_EMAIL", "president@whitehouse.gov"),
		SMTPSenderName:     getEnv("SMTP_SENDER_NAME", "Donald Trump"),
		SMTPSenderUser:     getEnv("SMTP_USER", ""),
		SMTPSenderPass:     getEnv("SMTP_PASS", ""),
		InsecureSkipVerify: getEnv("INSECURE_SKIP_VERIFY", "true") == "true",
		DirectMode:         getEnv("DIRECT_MODE", "false") == "true",
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
