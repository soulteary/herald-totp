# Build stage
FROM golang:1.26.6-alpine3.23 AS Builder
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
    go build -ldflags "-w -s -X 'github.com/soulteary/version-kit/v2.Version=$VERSION' -X 'github.com/soulteary/version-kit/v2.Commit=$COMMIT' -X 'github.com/soulteary/version-kit/v2.BuildDate=$BUILD_DATE'" -o herald-totp .

# Runtime stage
FROM alpine:3.23
RUN apk add --no-cache ca-certificates && \
    addgroup -S -g 10001 herald && \
    adduser -S -D -H -u 10001 -G herald herald
COPY --from=builder --chown=herald:herald /app/herald-totp /bin/herald-totp
USER 10001:10001
EXPOSE 8084
CMD ["herald-totp"]
