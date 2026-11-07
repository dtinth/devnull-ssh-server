FROM golang:1.27.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /devnull-ssh . && mkdir /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /devnull-ssh /devnull-ssh
COPY --from=build --chown=nonroot:nonroot /data /data
ENV DEVNULL_SSH_HOST_KEY=/data/ssh_host_ed25519_key
VOLUME /data
EXPOSE 2222
ENTRYPOINT ["/devnull-ssh"]
