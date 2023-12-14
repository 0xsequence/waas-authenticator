CONFIG           ?= $(TOP)/etc/waas-auth.conf

TOP              := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
SHELL            = bash -o pipefail
TEST_FLAGS       ?= -v

GITTAG           ?= $(shell git describe --exact-match --tags HEAD 2>/dev/null || :)
GITBRANCH        ?= $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || :)
LONGVERSION      ?= $(shell git describe --tags --long --abbrev=8 --always HEAD)$(echo -$GITBRANCH | tr / - | grep -v '\-master' || :)
VERSION          ?= $(if $(GITTAG),$(GITTAG),$(LONGVERSION))
GITCOMMIT        ?= $(shell git log -1 --date=iso --pretty=format:%H)
GITCOMMITDATE    ?= $(shell git log -1 --date=iso --pretty=format:%cd)
GITCOMMITAUTHOR  ?= $(shell git log -1 --date=iso --pretty="format:%an")


define run
	@go run github.com/goware/rerun/cmd/rerun -watch ./ -ignore vendor bin tests data/schema -run \
		'GOGC=off go build -o ./bin/$(1) ./cmd/$(1)/main.go && CONFIG=$(CONFIG) ./bin/$(1)'
endef

run:
	$(call run,waas-auth)

up:
	docker-compose up

build:
	GOGC=off GOBIN=$$PWD/bin \
	go install -v \
		-gcflags='-e' \
		-ldflags='-X "github.com/0xsequence/waas-authenticator.VERSION=$(VERSION)" -X "github.com/0xsequence/waas-authenticator.GITBRANCH=$(GITBRANCH)" -X "github.com/0xsequence/waas-authenticator.GITCOMMIT=$(GITCOMMIT)" -X "github.com/0xsequence/waas-authenticator.GITCOMMITDATE=$(GITCOMMITDATE)" -X "github.com/0xsequence/waas-authenticator.GITCOMMITAUTHOR=$(GITCOMMITAUTHOR)"' \
		./cmd/waas-auth

generate:
	go generate ./...

.PHONY: proto
proto:
	go generate ./proto

clean:
	rm -rf ./bin/*
	go clean -cache -testcache

test: test-clean
	GOGC=off go test $(TEST_FLAGS) -run=$(TEST) ./...

test-clean:
	GOGC=off go clean -testcache
