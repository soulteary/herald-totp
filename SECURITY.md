# Security

Security practices for herald-totp are documented in the docs:

- **[English](docs/enUS/SECURITY.md)** – Encryption key, API Key / HMAC, credential storage, production recommendations
- **[中文](docs/zhCN/SECURITY.md)** – 加密密钥、API Key / HMAC、凭证存储、生产环境建议

**Summary**: Use `HERALD_TOTP_ENCRYPTION_KEY` (32 bytes) for secret encryption and keep it secret; use `API_KEY` or HMAC for service-to-service auth in production; store secrets in environment variables or a secret manager (never in code or committed config); run herald-totp in a private network and put HTTPS in front when exposed.

To report a security vulnerability, please open a private security advisory or contact the maintainers directly.
