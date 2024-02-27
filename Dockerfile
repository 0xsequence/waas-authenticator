#
# Enclave base image
#
FROM golang:1.21.7-alpine3.19@sha256:163801a964d358d6450aeb51b59d5c807d43a7c97fed92cc7ff1be5bd72811ab AS base

RUN apk add make bash

#
# Enclave pre-image
#
FROM base AS builder

WORKDIR /go/src/github.com/0xsequence/waas-authenticator

ADD ./ ./

ARG VERSION

RUN make VERSION=${VERSION} build

#
# Enclave dev image
#
FROM base AS dev

WORKDIR /go/src/github.com/0xsequence/waas-authenticator

ENV CONFIG=./etc/waas-auth.conf

CMD ["make", "run"]


FROM ghcr.io/0xsequence/eiffel:v0.3.0@sha256:d4aa946d7eb587e0554123efc3eaa5830a1428b0325ea239fe489e372f573dfe

ARG ENV_ARG=dev2

RUN mkdir /workspace

ADD ./.eiffel/ /workspace/
ADD ./etc/waas-auth.${ENV_ARG}.conf /workspace/waas-auth.conf
COPY --from=builder /go/src/github.com/0xsequence/waas-authenticator/bin/waas-auth /workspace/waas-auth

CMD ["waas-auth"]
