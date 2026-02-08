package config

import (
	"os"
)

type Config struct {
	Port               string
	SMTPHost           string
	SMTPPort           string
	SMTPSenderEmail    string
	SMTPSenderUser     string // For AUTH
	SMTPSenderPass     string // For AUTH
	InsecureSkipVerify bool
}

func Load() *Config {
	return &Config{
		Port:               getEnv("PORT", "8080"),
		SMTPHost:           getEnv("SMTP_HOST", "localhost"),
		SMTPPort:           getEnv("SMTP_PORT", "1025"),
		SMTPSenderEmail:    getEnv("SMTP_SENDER_EMAIL", "president@whitehouse.gov"),
		SMTPSenderUser:     getEnv("SMTP_USER", ""),
		SMTPSenderPass:     getEnv("SMTP_PASS", ""),
		InsecureSkipVerify: getEnv("INSECURE_SKIP_VERIFY", "true") == "true",
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
