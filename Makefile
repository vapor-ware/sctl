test:
	go test -v
clean:
	rm -rf dist vendor sctl parts prime stage *.snap

snap:
	snapcraft

snap-clean:
	snapcraft clean

