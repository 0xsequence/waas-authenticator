#
# Enclave base image
#
FROM golang:1.21-bullseye@sha256:a8712f27d9ac742e7bded8f81f7547c5635e855e8b80302e8fc0ce424f559295 AS base
ENV DEBIAN_FRONTEND=noninteractive

ADD --chmod=0755 --checksum=sha256:4c97fd03a3b181996b1473f3a99b69a1efc6ecaf2b4ede061b6bd60a96b9325a \
  https://raw.githubusercontent.com/reproducible-containers/repro-sources-list.sh/v0.1.0/repro-sources-list.sh \
  /usr/local/bin/repro-sources-list.sh

RUN \
    repro-sources-list.sh && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
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

ADD ./ ./

RUN make build

#
# Enclave dist image
#
FROM amazonlinux:2023.3.20240131.0@sha256:62ebd855c09b363009221442fcb1d09aca167d4ba58f2cfd14e00e59ca2f2d54 AS api

#RUN yum update -y && \
#    yum install -y chrony && \
#    echo "refclock PHC /dev/ptp0 poll 2" >> /etc/chrony.d/kvm-ptp.conf && \
#    rm /etc/chrony.d/*.sources

WORKDIR /app

ADD ./docker/run.sh ./

COPY --from=builder /go/src/github.com/0xsequence/waas-authenticator/bin/waas-auth ./

ARG ENV_ARG=dev2
ADD --chown=authenticator:authenticator ./etc/waas-auth.${ENV_ARG}.conf /etc/waas-auth.conf
ENV CONFIG=/etc/waas-auth.conf

CMD ["/app/run.sh"]

#
# Enclave dev image
#
FROM base AS dev

WORKDIR /go/src/github.com/0xsequence/waas-authenticator

ENV CONFIG=./etc/waas-auth.conf

CMD ["make", "run"]
