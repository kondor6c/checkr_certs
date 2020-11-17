
all: build test

SHELL := /bin/bash
BINARY = main
BIN_DIR = $(shell echo $${GOPATH:-~/go} | awk -F':' '{ print $$1 "/bin"}')

GO ?= go
GOFLAGS :=
VERSION_STR = ""
COMMIT_SHA=$(shell git rev-parse --short HEAD)
#VERSION_STR = "-X github.com/greenplum-db/gpmigrate/migrate.version=$(shell date +%Y-%m-%d)"

.PHONY: depend format unit coverage build build_mac build_linux clean

depend:
	go get golang.org/x/tools/cmd/goimports
	go get github.com/golang/lint/golint
	go get github.com/onsi/ginkgo/ginkgo
	go get github.com/alecthomas/gometalinter
	gometalinter --install
	go get github.com/golang/dep/cmd/dep
	dep ensure

format:
	gofmt -w -s main.go pkg
	goimports -w main.go pkg

lint: golangci-lint
	.PHONY: lint
	@echo "Linting vs commit '$(call err_if_empty,EPOCH_TEST_COMMIT)'"
ifeq ($(PRE_COMMIT),)
	@echo "FATAL: pre-commit was not found, make .install.pre-commit to installing it." >&2
	@exit 2
endif
	$(PRE_COMMIT) run -a
	#gometalinter --config=gometalinter.config -s vendor ./...
	#gometalinter -s vendor ./...
embed: go-bindata generate build

unit: format
	ginkgo -r -cover -coverprofile=coverage.out pkg/add

coverage: unit
	go tool cover -func=pkg/add/coverage.out

#end2end:
#	ginkgo -r end2end

build: format
	$(GO) build -tags '$(BINARY)' $(GOFLAGS) -o $(BIN_DIR)/$(BINARY) 

build_linux: format
	env GOOS=linux GOARCH=amd64 go build -tags '$(BINARY)' $(GOFLAGS) -o $(BINARY)_linux -ldflags $(VERSION_STR)

clean:
	rm -f $(BINARY)_linux $(BIN_DIR)/$(BINARY) ./coverage.out
