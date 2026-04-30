# Multi-stage Dockerfile that produces two thin images:
#   - yauth-app:   the application binary (config-driven server)
#   - yauth-cli:   the `yauth` CLI used by the migrate Job
#
# Build:
#   docker build -t yauth-app:latest --target app .
#   docker build -t yauth-cli:latest --target cli .
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/yauth-app ./examples/config && \
    CGO_ENABLED=0 go build -o /out/yauth ./cmd/yauth

FROM gcr.io/distroless/static:nonroot AS app
COPY --from=build /out/yauth-app /yauth-app
USER nonroot:nonroot
ENTRYPOINT ["/yauth-app"]
CMD ["-c", "/etc/yauth/yauth.yaml"]

FROM gcr.io/distroless/static:nonroot AS cli
COPY --from=build /out/yauth /yauth
USER nonroot:nonroot
ENTRYPOINT ["/yauth"]
