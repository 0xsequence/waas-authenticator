CONFIG           ?= $(TOP)/etc/waas-auth.conf
ENV              ?= prod

TOP              := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
SHELL            = bash -o pipefail
TEST_FLAGS       ?= -v

define run
	@go run github.com/goware/rerun/cmd/rerun -watch ./ -ignore vendor bin tests data/schema -run \
		'GOGC=off go build -o ./bin/$(1) ./cmd/$(1)/main.go && CONFIG=$(CONFIG) ./bin/$(1)'
endef

run:
	$(call run,waas-auth)

up:
	docker-compose up

define build
	CGO_ENABLED=0 \
	GOARCH=amd64 \
	GOOS=linux \
	go build -v \
		-trimpath \
		-buildvcs=false \
		-ldflags='-s -w -buildid=' \
		-o ./bin/$(1) \
		./cmd/$(1)
endef

build: build-utils build-waas-auth

build-waas-auth:
	$(call build,waas-auth)

build-utils: build-jwt-util

build-jwt-util:
	$(call build,jwt-util)

generate:
	go generate -x ./...

.PHONY: proto
proto:
	go generate -x ./proto

clean:
	rm -rf ./bin/*
	rm -rf version.go
	go clean -cache -testcache

test: test-clean
	GOGC=off go test $(TEST_FLAGS) -run=$(TEST) ./...

test-clean:
	GOGC=off go clean -testcache

eif: clean ensure-version
	@mkdir -p bin
	docker build --platform linux/amd64 --build-arg VERSION=$(VERSION) --build-arg ENV_ARG=$(ENV) -t waas-authenticator-builder .
	docker run --platform linux/amd64 -v $(TOP)/bin:/out waas-authenticator-builder waas-auth.$(VERSION)

ensure-version:
	@test -n "$(VERSION)" || (echo "Oops! you forgot to pass the VERSION env variable, try: make VERSION=vX.X.X eif" && exit 1)
	@rm -rf version.go
	@echo "package waasauthenticator" > version.go
	@echo "const VERSION = \"$(VERSION)\"" >> version.go
