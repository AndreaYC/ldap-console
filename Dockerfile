# Local use only: publish with -p 127.0.0.1:PORT:8389 (make docker-run does).
# The console has no login; publishing on all interfaces exposes the
# directory, with your bind account's rights, to your whole network.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -tags timetzdata -ldflags="-s -w" -o /out/ldap-console ./cmd/ldap-console \
 && mkdir -p /out/config/ldap-console

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ldap-console /usr/local/bin/ldap-console
COPY --from=build --chown=65532:65532 /out/config /home/nonroot/.config
VOLUME /home/nonroot/.config/ldap-console
EXPOSE 8389
ENTRYPOINT ["/usr/local/bin/ldap-console", "-container", "-listen", "0.0.0.0:8389"]
