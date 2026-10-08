# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

# Base images are pinned to multi-arch index digests. Refresh with
#   docker buildx imagetools inspect <image>:<tag>
# golang:1.27 resolved to 1.27.1-trixie on 2026-10-07.
FROM --platform=$BUILDPLATFORM golang:1.27@sha256:162be5298a40ed317005c8339c6de4d10d3eef336d66dc8e9259b03ab9d3a6d2 AS build
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

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/arc-gocacheprog-server /usr/local/bin/arc-gocacheprog-server
COPY --from=build /out/arc-gocacheprog /usr/local/bin/arc-gocacheprog
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/arc-gocacheprog-server"]
CMD ["-config", "/etc/arc-gocacheprog/config.yaml"]
