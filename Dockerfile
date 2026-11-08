# check=skip=SecretsUsedInArgOrEnv
# (that check takes DEVNULL_SSH_HOST_KEY, the path of the host key, for a secret)
# The build stage runs on the build machine and cross-compiles, so a multi-platform image needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.3 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /devnull-ssh . && mkdir /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /devnull-ssh /devnull-ssh
COPY --from=build --chown=nonroot:nonroot /data /data
ENV DEVNULL_SSH_HOST_KEY=/data/ssh_host_ed25519_key
VOLUME /data
EXPOSE 2222
ENTRYPOINT ["/devnull-ssh"]
