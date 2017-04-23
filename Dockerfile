FROM golang:1.8.0

MAINTAINER Hayahito Kawamitsu

RUN go get github.com/mittz/docker-machine-driver-ecl2
RUN go build -o /usr/local/bin/docker-machine-driver-ecl2 github.com/mittz/docker-machine-driver-ecl2/bin/
