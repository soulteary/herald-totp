# Documentation Index

Welcome to the herald-totp documentation. herald-totp is the TOTP 2FA service for [Herald](https://github.com/soulteary/herald) and [Stargate](https://github.com/soulteary/stargate).

## Multi-language Documentation

- [English](README.md) | [中文](../zhCN/README.md)

## Document List

### Core Documents

- **[README.md](../../README.md)** - Project overview and quick start guide

### Detailed Documents

- **[API.md](API.md)** - Complete API reference
  - Base URL and authentication (API Key / HMAC)
  - POST /v1/enroll/start, POST /v1/enroll/confirm
  - POST /v1/verify (TOTP or backup code)
  - GET /v1/status
  - GET /healthz
  - Error codes and HTTP status codes

- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Deployment guide
  - Binary and Docker run
  - Configuration options (encryption key, Redis, TOTP params, rate limits)
  - Integration with Stargate
  - Health and monitoring

- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Troubleshooting guide
  - Enroll/verify failures
  - 401 unauthorized
  - config_error (missing encryption key)
  - rate_limited, replay, expired
  - Redis connectivity

- **[SECURITY.md](SECURITY.md)** - Security practices
  - Encryption key and API Key / HMAC
  - Credential storage
  - Production recommendations

## Quick Navigation

### Getting Started

1. Read [README.md](../../README.md) to understand the project
2. Check the [Quick Start](../../README.md#quick-start) section
3. Refer to [DEPLOYMENT.md](DEPLOYMENT.md) for configuration and Stargate integration

### Developers

1. Check [API.md](API.md) for the enroll/verify contract and error codes
2. Review [DEPLOYMENT.md](DEPLOYMENT.md) for deployment options

### Operations

1. Read [DEPLOYMENT.md](DEPLOYMENT.md) for deployment and Stargate config
2. Refer to [SECURITY.md](SECURITY.md) for production practices
3. Troubleshoot issues: [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

## Document Structure

```
herald-totp/
├── README.md              # Main project document (English)
├── README.zhCN.md         # Main project document (Chinese)
├── docs/
│   ├── enUS/
│   │   ├── README.md       # Documentation index (this file)
│   │   ├── API.md          # API reference
│   │   ├── DEPLOYMENT.md   # Deployment guide
│   │   ├── TROUBLESHOOTING.md # Troubleshooting guide
│   │   └── SECURITY.md     # Security practices
│   └── zhCN/
│       ├── README.md       # Documentation index (Chinese)
│       ├── API.md          # API reference (Chinese)
│       ├── DEPLOYMENT.md   # Deployment guide (Chinese)
│       ├── TROUBLESHOOTING.md # Troubleshooting guide (Chinese)
│       └── SECURITY.md     # Security practices (Chinese)
└── ...
```

## Find by Topic

- API endpoints and auth: [API.md](API.md)
- Configuration and Stargate integration: [DEPLOYMENT.md](DEPLOYMENT.md)
- Common issues: [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- Security: [SECURITY.md](SECURITY.md)
