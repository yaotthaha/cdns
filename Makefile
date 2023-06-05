NAME = cdns

build:
	@go build -o $(NAME) -v -trimpath -ldflags "-s -w -buildid=" .

fmt:
	@gofumpt -l -w .
	@gofmt -s -w .
	@gci write --custom-order -s standard -s "prefix(github.com/yaotthaha/)" -s "default" .

fmt_install:
	go install -v mvdan.cc/gofumpt@latest
	go install -v github.com/daixiang0/gci@latest
