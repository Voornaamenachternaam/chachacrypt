# Builder: use the exact Go version declared in go.mod
FROM golang:1.25.6 AS builder
WORKDIR /src
COPY . .
# Build a static linux binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /usr/local/bin/chachacrypt .

# Runtime: small Debian with bash so you can exec /bin/bash
FROM debian:stable-slim
# Keep image minimal but ensure bash and ssl certs available
RUN apt-get update && \
    apt-get install -y --no-install-recommends bash ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/chachacrypt /usr/local/bin/chachacrypt
RUN chmod +x /usr/local/bin/chachacrypt

# Keep container running so you can `docker exec -it <c> /bin/bash` or run the CLI via exec
CMD ["sleep", "infinity"]
