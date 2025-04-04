# Build stage
FROM golang:latest AS build

WORKDIR /app

# Copy go mod and sum first to leverage caching
COPY go.mod .
COPY go.sum .

# Download dependencies
RUN go mod download

# Copy the rest of the code
COPY . .

# Build the binary from chachacrypt.go
RUN go build -o /chachacrypt ./chachacrypt.go

# Run stage
FROM ubuntu:latest AS run

# Copy the binary from the build stage
COPY --from=build /chachacrypt /chachacrypt

# Set working directory (optional)
WORKDIR /app

# Expose port (optional, based on your app needs)
EXPOSE 8080

# Command to run the binary
CMD ["/chachacrypt"]
