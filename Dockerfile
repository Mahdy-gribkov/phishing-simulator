# Stage 1: Builder
FROM golang:1.24.13-alpine AS builder

# Install ca-certificates and git
RUN apk add --no-cache ca-certificates git

WORKDIR /app

# Copy go mod file
COPY go.mod ./
# Download dependencies (if any)
RUN go mod download

# Copy source code
COPY . .

# Build the binary
# CGO_ENABLED=0 for static binary
RUN CGO_ENABLED=0 GOOS=linux go build -o phishing-simulator .

# Stage 2: Runtime
FROM scratch

# Copy CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary
COPY --from=builder /app/phishing-simulator /phishing-simulator

# Expose port (documentary)
EXPOSE 8080

# Run
ENTRYPOINT ["/phishing-simulator"]
