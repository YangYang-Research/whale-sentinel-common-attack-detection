# First Stage: Build the Go Application
FROM golang:1.24.0-alpine AS builder

# Set the working directory
WORKDIR /app

# Copy the Go source code
COPY . /app/whale-sentinel-common-attack-detection

# Install dependencies (if needed)
WORKDIR /app/whale-sentinel-common-attack-detection

RUN go mod tidy

# Build the Go application
RUN go build -o whale-sentinel-common-attack-detection .

# Second Stage: Nginx + Self-Signed SSL + Go App
FROM nginx:stable-alpine

# Install OpenSSL for SSL certificate generation
RUN apk add --no-cache openssl

# Create directory for SSL certificates
RUN mkdir -p /etc/nginx/certs

# Generate self-signed certificate (valid for 1 year)
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/certs/server.key -out /etc/nginx/certs/server.crt \
    -subj "/CN=localhost"

# Copy the Go application from the builder stage
COPY --from=builder /app/whale-sentinel-common-attack-detection /usr/local/bin/

# Copy custom Nginx config to enable HTTPS and proxy to the Go app
COPY --from=builder /app/whale-sentinel-common-attack-detection/nginx.conf /etc/nginx/nginx.conf

# Expose HTTPS port
EXPOSE 443

# Command to run both Nginx and Go app
CMD ["sh", "-c", "nginx && /usr/local/bin/whale-sentinel-common-attack-detection"]
