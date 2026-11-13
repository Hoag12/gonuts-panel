# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=arm64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/gonuts-panel ./cmd/gonuts-panel

FROM alpine:3.22
RUN adduser -D -u 1000 gonuts \
 && apk add --no-cache ca-certificates tzdata \
 && mkdir -p /data && chown gonuts:gonuts /data
COPY --from=build /out/gonuts-panel /usr/local/bin/gonuts-panel
USER gonuts
VOLUME ["/data"]
EXPOSE 10000
ENTRYPOINT ["gonuts-panel"]
