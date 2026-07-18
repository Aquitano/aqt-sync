# Build a static aqt-server binary (pure Go, CGO off) and ship it in a distroless
# image. modernc.org/sqlite is pure Go, so no C toolchain or libc is needed.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/aqt-server ./cmd/aqt-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/aqt-server /usr/local/bin/aqt-server
ENV AQT_DATA_DIR=/data AQT_ADDR=0.0.0.0:8080 AQT_ALLOW_INSECURE_HTTP=1
VOLUME ["/data"]
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/aqt-server"]
