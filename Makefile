test:
	go test -cover -v ./...

clean:
	rm -rf dist vendor sctl sctl.exe

fmt:
	@find . -name '*.go' -not -wholename './vendor/*' | while read -r file; do goimports -w "$$file"; done

lint:
	@golint -set_exit_status

snapshot:
	goreleaser release --debug --snapshot --skip-publish --rm-dist
