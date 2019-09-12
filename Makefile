test:
	go test -v
clean:
	rm -rf dist vendor sctl parts prime stage *.snap *.xdelta3

fmt:
	@find . -name '*.go' -not -wholename './vendor/*' | while read -r file; do goimports -w "$$file"; done

lint:
	@golint -set_exit_status

snap:
	snapcraft

snap-clean:
	snapcraft clean

