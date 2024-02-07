#
# Enclave base image
#
FROM golang:1.21-bullseye@sha256:a8712f27d9ac742e7bded8f81f7547c5635e855e8b80302e8fc0ce424f559295 AS base

#
# Enclave pre-image
#
FROM base AS builder
ARG SOURCE_DATE_EPOCH

WORKDIR /go/src/github.com/0xsequence/waas-authenticator

ADD ./ ./

RUN make build

#
# Enclave dist image
#
FROM amazonlinux:2023.3.20240131.0@sha256:62ebd855c09b363009221442fcb1d09aca167d4ba58f2cfd14e00e59ca2f2d54 AS apibase
ARG SOURCE_DATE_EPOCH

RUN dnf install -y findutils chrony && \
    echo "refclock PHC /dev/ptp0 poll 2" >> /etc/chrony.d/kvm-ptp.conf

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

# Limit the timestamp upper bound to SOURCE_DATE_EPOCH.
# Workaround for https://github.com/moby/buildkit/issues/3180
#RUN cd / && find $( ls / | grep -E -v "^(dev|mnt|proc|sys)$" ) \
RUN cd / && find $( ls / | grep -E -v "^(proc)$") \
  -newermt "@${SOURCE_DATE_EPOCH}" -writable -xdev \
  | xargs touch --date="@${SOURCE_DATE_EPOCH}" --no-dereference

# Squash the entire stage for resetting the whiteout timestamps.
# Workaround for https://github.com/moby/buildkit/issues/3168
FROM scratch AS api
WORKDIR /app
COPY --from=apibase / /

#
# Enclave dev image
#
FROM base AS dev

WORKDIR /go/src/github.com/0xsequence/waas-authenticator

ENV CONFIG=./etc/waas-auth.conf

CMD ["make", "run"]
