TEST_FLAGS ?= -p 1 -v

all:
	@echo "See Makefile contents for details."

test: go-test

go-test:
	go clean -testcache && go test $(TEST_FLAGS) -run=$(TEST) ./...

clean:
	@go clean -testcache

build:
	go build ./...
