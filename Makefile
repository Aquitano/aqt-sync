.PHONY: build build-server test test-short test-race vet fmt restore-drill docker clean

# Build both binaries into ./bin.
build:
	go build -o bin/aqt ./cmd/aqt
	go build -o bin/aqt-server ./cmd/aqt-server

build-server:
	go build -o bin/aqt-server ./cmd/aqt-server

test:
	go test ./...

test-short:
	go test -short ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

# Full backup -> restore -> byte-diff drill against real built binaries.
restore-drill:
	./scripts/restore-drill.sh

docker:
	docker build -t aqt-server .

clean:
	rm -rf bin
