# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w" -o /out/arc-gocacheprog-server ./cmd/arc-gocacheprog-server && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w" -o /out/arc-gocacheprog ./cmd/arc-gocacheprog

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/arc-gocacheprog-server /usr/local/bin/arc-gocacheprog-server
COPY --from=build /out/arc-gocacheprog /usr/local/bin/arc-gocacheprog
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/arc-gocacheprog-server"]
CMD ["-config", "/etc/arc-gocacheprog/config.yaml"]
