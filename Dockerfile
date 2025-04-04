FROM golang:latest as build

WORKDIR /app

# Copy the Go module files
COPY go.mod .
COPY go.sum .

# Download the Go module dependencies
RUN go mod download

COPY . .

RUN go build -o /chachacrypt ./cmd/web/...
 
FROM ubuntu:latest as run

# Copy the application executable from the build image
COPY --from=build /chachacrypt /chachacrypt

WORKDIR /app
EXPOSE 8080
CMD ["/chachacrypt"]
