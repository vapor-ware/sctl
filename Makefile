test:
	@ # Note: this requires go1.10+ in order to do multi-package coverage reports
	go test -race -v -coverprofile=coverage.out -covermode=atomic ./...

report:
	@if test -f "coverage.out"; then go tool cover -html=coverage.out; else echo "run 'make test' to generate coverage file"; fi

clean:
	rm -rf dist vendor sctl sctl.exe coverage.out

fmt:
	@find . -name '*.go' -not -wholename './vendor/*' | while read -r file; do goimports -w "$$file"; done

lint:
	@golint -set_exit_status

snapshot:
	goreleaser release --debug --snapshot --skip-publish --rm-dist
