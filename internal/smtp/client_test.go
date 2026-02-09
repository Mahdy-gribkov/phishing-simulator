package smtp

import "testing"

func TestSenderDomain(t *testing.T) {
	tests := []struct {
		email string
		want  string
	}{
		{"user@example.com", "example.com"},
		{"ceo@whitehouse.gov", "whitehouse.gov"},
		{"noat", "localhost"},
		{"", "localhost"},
		{"multi@at@domain.com", "domain.com"},
	}
	for _, tt := range tests {
		if got := senderDomain(tt.email); got != tt.want {
			t.Errorf("senderDomain(%q) = %q, want %q", tt.email, got, tt.want)
		}
	}
}

func TestNewClient(t *testing.T) {
	c := NewClient("smtp.example.com", "587", "user", "pass", "envelope@relay.com", "spoofed@fake.org", "Test Name", false, "", "", "")

	if c.Host != "smtp.example.com" {
		t.Errorf("Host = %q, want smtp.example.com", c.Host)
	}
	if c.EnvelopeSender != "envelope@relay.com" {
		t.Errorf("EnvelopeSender = %q, want envelope@relay.com", c.EnvelopeSender)
	}
	if c.SenderEmail != "spoofed@fake.org" {
		t.Errorf("SenderEmail = %q, want spoofed@fake.org", c.SenderEmail)
	}
	if c.SenderName != "Test Name" {
		t.Errorf("SenderName = %q, want Test Name", c.SenderName)
	}
}
