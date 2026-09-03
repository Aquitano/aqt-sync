.PHONY: build build-server test test-short test-race vet lint fmt fuzz restore-drill docker clean

# Build the CLI and server into ./bin. aqt is a multi-call binary: Git reaches its
# remote helper through a link named git-remote-aqt, which is what `aqt git setup`
# creates next to an installed client.
build:
	go build -o bin/aqt ./cmd/aqt
	ln -sf aqt bin/git-remote-aqt
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

lint:
	golangci-lint run ./...
	GOOS=windows golangci-lint run ./...

# Run every fuzz target for a short burst. Native fuzzing runs one target per
# invocation, so each decoder is listed explicitly.
fuzz:
	go test -run='^$$' -fuzz='^FuzzDecodeResourceUpload$$' -fuzztime=10s ./internal/api
	go test -run='^$$' -fuzz='^FuzzDecodeResourceDownload$$' -fuzztime=10s ./internal/api
	go test -run='^$$' -fuzz='^FuzzResourceUploadRoundTrip$$' -fuzztime=10s ./internal/api
	go test -run='^$$' -fuzz='^FuzzResourceDownloadRoundTrip$$' -fuzztime=10s ./internal/api
	go test -run='^$$' -fuzz='^FuzzParsePackIndex$$' -fuzztime=10s ./internal/server
	go test -run='^$$' -fuzz='^FuzzPackRoundTrip$$' -fuzztime=10s ./internal/server
	go test -run='^$$' -fuzz='^FuzzParseRef$$' -fuzztime=10s ./cmd/aqt
	go test -run='^$$' -fuzz='^FuzzSplitRefPath$$' -fuzztime=10s ./cmd/aqt
	go test -run='^$$' -fuzz='^FuzzDecodeBase$$' -fuzztime=10s ./internal/folderstate
	go test -run='^$$' -fuzz='^FuzzMergeModeEditScripts$$' -fuzztime=10s ./cmd/aqt
	go test -run='^$$' -fuzz='^FuzzChangesReconstructsTarget$$' -fuzztime=10s ./internal/syncengine/merge
	go test -run='^$$' -fuzz='^FuzzThreeWayCleanLinesComeFromInputs$$' -fuzztime=10s ./internal/syncengine/merge
	go test -run='^$$' -fuzz='^FuzzDecodeFragment$$' -fuzztime=10s ./internal/crypto
	go test -run='^$$' -fuzz='^FuzzFragmentRoundTrip$$' -fuzztime=10s ./internal/crypto

fmt:
	gofmt -l -w .

# Full backup -> restore -> byte-diff drill against real built binaries.
restore-drill:
	./scripts/restore-drill.sh

docker:
	docker build -t aqt-server .

clean:
	rm -rf bin
