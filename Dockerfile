# Build stage
FROM golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder
RUN apk add --no-cache git
WORKDIR /app
ENV CGO_ENABLED=0 GOOS=linux
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build args for version info (CI/release)
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE
RUN BUILD_DATE=${BUILD_DATE:-$(date +%FT%T%z)} && \
    go build -ldflags "-w -s -X 'github.com/soulteary/version-kit/v4.Version=$VERSION' -X 'github.com/soulteary/version-kit/v4.Commit=$COMMIT' -X 'github.com/soulteary/version-kit/v4.BuildDate=$BUILD_DATE'" -o herald-totp .

# Runtime stage
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache ca-certificates && \
    addgroup -S -g 10001 herald && \
    adduser -S -D -H -u 10001 -G herald herald
COPY --from=builder --chown=herald:herald /app/herald-totp /bin/herald-totp
USER 10001:10001
EXPOSE 8084
CMD ["herald-totp"]
