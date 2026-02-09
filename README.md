# Phishing Email Simulator

A Go web application that sends emails with spoofed sender headers via SMTP,
demonstrating email spoofing techniques and why SPF/DKIM/DMARC exist.

> **Educational use only.** Sending spoofed emails without consent is illegal.

## Quick Start

```bash
cp .env.example .env   # fill in your SMTP relay credentials
go run .               # http://localhost:8080
```

### Docker

```bash
docker compose up app                  # production (uses .env)
docker compose --profile dev up        # local dev (Mailpit at :8025)
```

### Kubernetes

```bash
docker build -t phishing-simulator:latest .
kubectl create secret generic smtp-credentials \
  --from-literal=host=smtp-relay.brevo.com \
  --from-literal=username=you@email.com \
  --from-literal=password=your-smtp-key
kubectl apply -f k8s/
```

## SMTP Relay Setup

The app needs an SMTP relay to deliver emails. Recommended: [Brevo](https://brevo.com) (free, 300 emails/day).

1. Sign up → Settings → SMTP & API → generate SMTP key
2. Verify your sender email under Senders & Domains
3. Fill `.env` with your SMTP login, key, and verified sender address

## How It Works

The application manually constructs SMTP messages at the protocol level:

1. TCP connection to relay on port 587
2. EHLO handshake → STARTTLS upgrade → AUTH PLAIN
3. `MAIL FROM` uses the authenticated relay account (envelope sender)
4. RFC 5322 headers are crafted manually — the `From:` header carries the
   spoofed display name and a configurable email address

The key insight: the SMTP envelope sender and the `From:` header are independent.
The relay authenticates the envelope sender, but the display `From:` is just text
controlled by the sending application.

## Why the Email Triggers Security Warnings

When the `From:` header domain differs from the envelope sender or lacks proper
DNS records, receiving mail servers flag the message:

### SPF (Sender Policy Framework) — FAILS

SPF checks whether the sending server's IP is authorized for the `From:` domain
via a DNS TXT record. If the domain's SPF record doesn't include the relay's IP,
SPF fails.

### DKIM (DomainKeys Identified Mail) — FAILS / MISSING

DKIM requires a cryptographic signature added by the sending domain's mail server.
Without the domain's private DKIM key, the signature is missing or misaligned.

### DMARC (Domain-based Message Authentication, Reporting & Conformance) — FAILS

DMARC ties SPF and DKIM together with a policy. If both fail or aren't aligned
with the `From:` domain, DMARC instructs the receiver to reject or quarantine
the message.

## What Would Be Required for Real-World Authentication

To make such an email pass all checks:

1. **Own the domain** used in the `From:` header
2. **SPF**: publish a DNS TXT record authorizing the relay's IP
   (`v=spf1 include:sendinblue.com ~all`)
3. **DKIM**: add the relay's public key to DNS so it can sign outgoing mail
4. **DMARC**: publish a policy record (`v=DMARC1; p=quarantine; ...`)

Without domain ownership, spoofing a properly configured domain is not possible —
which is exactly the point of these mechanisms.

## Project Structure

```
main.go                     HTTP server, routes, input validation
config/config.go            Environment variable configuration
internal/smtp/client.go     Raw SMTP protocol implementation
web/templates/form.html     Web UI form
Dockerfile                  Multi-stage build (alpine → scratch)
docker-compose.yml          Production + dev (Mailpit) profiles
k8s/deployment.yaml         Kubernetes Deployment with Secret refs
k8s/service.yaml            Kubernetes ClusterIP Service
```
