NAME = cdns
VERSION = $(shell git describe --tags --abbrev=0)
COMMIT = $(shell git rev-parse HEAD)

build:
	@go build -o $(NAME) -v -trimpath -ldflags "-X 'github.com/yaotthaha/cdns/constant.Commit=$(COMMIT)' -X 'github.com/yaotthaha/cdns/constant.Version=$(VERSION)' -s -w -buildid=" .

fmt:
	@gofumpt -l -w .
	@gofmt -s -w .
	@gci write --custom-order -s standard -s "prefix(github.com/yaotthaha/)" -s "default" .

fmt_install:
	go install -v mvdan.cc/gofumpt@latest
	go install -v github.com/daixiang0/gci@latest
