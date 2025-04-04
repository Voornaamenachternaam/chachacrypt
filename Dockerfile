FROM ubuntu:latest as builder
RUN mkdir -p home/app
WORKDIR home/app
COPY . .
RUN go build
