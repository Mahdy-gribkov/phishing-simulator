# Stage 1: Builder
FROM golang:1.24.13-alpine AS builder

RUN apk add --no-cache ca-certificates git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o phishing-simulator .

# Stage 2: Runtime - alpine with Perl for swaks direct delivery
FROM alpine:3.21

RUN apk add --no-cache ca-certificates perl perl-net-ssleay perl-io-socket-ssl

WORKDIR /app

COPY --from=builder /app/phishing-simulator .
COPY --from=builder /app/swaks.pl .
COPY --from=builder /app/web/ ./web/

EXPOSE 8080

ENTRYPOINT ["./phishing-simulator"]
