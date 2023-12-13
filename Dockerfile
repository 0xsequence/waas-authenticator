#
# Enclave base image
#
FROM golang:1.20.3-bullseye AS base

RUN apt-get install -y --no-install-recommends \
    g++ \
    gcc \
    libc6-dev \
    make \
    pkg-config \
    bash \
    ca-certificates \
    git

#
# Enclave pre-image
#
FROM base AS builder

WORKDIR /go/src/github.com/0xsequence/waas-authenticator

ARG GITBRANCH=""
ARG GITCOMMIT=""
ARG GITCOMMITDATE=""
ARG VERSION=""

ADD go.mod go.sum ./

RUN go mod download

ADD ./ ./

RUN go build -o bin/waas-auth ./cmd/waas-auth

#
# Enclave dist image
#
FROM amazonlinux:2 AS api

RUN yum update -y && \
    yum install -y chrony && \
    echo "refclock PHC /dev/ptp0 poll 2" >> /etc/chrony.d/kvm-ptp.conf && \
    rm /etc/chrony.d/*.sources

WORKDIR /app

ADD ./docker ./

COPY --from=builder /go/src/github.com/0xsequence/waas-authenticator/bin/waas-auth ./
ADD --chown=authenticator:authenticator ./etc /etc/waas-auth

CMD ["/app/run.sh"]

#
# Enclave dev image
#
FROM base AS dev

WORKDIR /go/src/github.com/0xsequence/waas-authenticator

ENV CONFIG=./etc/dev2.toml

CMD ["make", "run"]
