.PHONY: build build-server test test-short test-race vet fmt fuzz restore-drill docker clean

# Build the CLI, Git helper, and server into ./bin.
build:
	go build -o bin/aqt ./cmd/aqt
	go build -o bin/git-remote-aqt ./cmd/git-remote-aqt
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

# Run every fuzz target for a short burst. Native fuzzing runs one target per
# invocation, so each decoder is listed explicitly.
fuzz:
	go test -run='^$$' -fuzz='^FuzzDecodeResourceUpload$$' -fuzztime=10s ./internal/api
	go test -run='^$$' -fuzz='^FuzzDecodeResourceDownload$$' -fuzztime=10s ./internal/api
	go test -run='^$$' -fuzz='^FuzzResourceUploadRoundTrip$$' -fuzztime=10s ./internal/api
	go test -run='^$$' -fuzz='^FuzzResourceDownloadRoundTrip$$' -fuzztime=10s ./internal/api
	go test -run='^$$' -fuzz='^FuzzParsePackIndex$$' -fuzztime=10s ./internal/server
	go test -run='^$$' -fuzz='^FuzzPackRoundTrip$$' -fuzztime=10s ./internal/server
	go test -run='^$$' -fuzz='^FuzzExtractTar$$' -fuzztime=10s ./internal/syncengine
	go test -run='^$$' -fuzz='^FuzzHashTar$$' -fuzztime=10s ./internal/syncengine
	go test -run='^$$' -fuzz='^FuzzParseRef$$' -fuzztime=10s ./cmd/aqt
	go test -run='^$$' -fuzz='^FuzzSplitRefPath$$' -fuzztime=10s ./cmd/aqt
	go test -run='^$$' -fuzz='^FuzzDecodeBase$$' -fuzztime=10s ./cmd/aqt
	go test -run='^$$' -fuzz='^FuzzMergeModeEditScripts$$' -fuzztime=10s ./cmd/aqt
	go test -run='^$$' -fuzz='^FuzzChangesReconstructsTarget$$' -fuzztime=10s ./internal/syncengine/merge
	go test -run='^$$' -fuzz='^FuzzThreeWayNeverInventsMarkers$$' -fuzztime=10s ./internal/syncengine/merge
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
