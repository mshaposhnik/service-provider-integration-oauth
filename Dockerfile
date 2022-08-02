FROM golang:1.18.5 as builder
ENV GOPATH=/go/
USER root

WORKDIR /spi-oauth

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
COPY static/callback_success.html static/callback_success.html
COPY static/callback_error.html static/callback_error.html
COPY static/redirect_notice.html static/redirect_notice.html

# Copy the go sources
COPY main.go main.go
COPY controllers/ controllers/

# build service
# Note that we're not running the tests here. Our integration tests depend on a running cluster which would not be
# available in the docker build.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o spi-oauth main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /spi-oauth/spi-oauth /spi-oauth
COPY --from=builder /spi-oauth/static/callback_success.html /static/callback_success.html
COPY --from=builder /spi-oauth/static/callback_error.html /static/callback_error.html
COPY --from=builder /spi-oauth/static/redirect_notice.html /static/redirect_notice.html

WORKDIR /
USER 65532:65532

ENTRYPOINT ["/spi-oauth"]

