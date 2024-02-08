#
# Enclave base image
#
FROM golang:1.21-bullseye@sha256:a8712f27d9ac742e7bded8f81f7547c5635e855e8b80302e8fc0ce424f559295 AS base

#
# Enclave pre-image
#
FROM base AS builder

WORKDIR /go/src/github.com/0xsequence/waas-authenticator

ADD ./ ./

RUN make build

#
# Enclave dev image
#
FROM base AS dev

WORKDIR /go/src/github.com/0xsequence/waas-authenticator

ENV CONFIG=./etc/waas-auth.conf

CMD ["make", "run"]


FROM local/eiffel:latest

ARG ENV_ARG=dev2

RUN mkdir /workspace

ADD ./.eiffel/ /workspace/
ADD ./etc/waas-auth.${ENV_ARG}.conf /workspace/waas-auth.conf
COPY --from=builder /go/src/github.com/0xsequence/waas-authenticator/bin/waas-auth /workspace/waas-auth

CMD ["waas-auth"]
