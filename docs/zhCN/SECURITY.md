# herald-totp 安全实践

本文说明 herald-totp 的安全注意事项与推荐做法。

## 加密密钥

- **HERALD_TOTP_ENCRYPTION_KEY** 为绑定与验证所必需，须为 32 字节（256 位）以用于 AES-256-GCM。未配置或长度不足时，enroll/confirm 与 verify 将失败（config_error）。
- 请严格保密该密钥，不得提交到代码库。应通过环境变量或密钥管理服务（如 Kubernetes Secrets、HashiCorp Vault）注入。本地开发可使用 `.env`，并确保 `.env` 已加入 `.gitignore`。
- 轮换密钥时需注意：Redis 中已加密的 TOTP 密钥无法用新密钥解密。若需轮换，请规划迁移（用户重新绑定或解密后重新加密）。

## API Key 与 HMAC

- 配置 **API_KEY** 后，herald-totp 会要求所有受保护接口（enroll、verify、status）的请求头 `X-API-Key` 与之一致。请使用足够强且唯一的密钥并妥善保管。
- Stargate 侧需配置相同的 `HERALD_TOTP_API_KEY`，以便在请求 herald-totp 时携带该密钥。
- 也可使用 **HMAC_SECRET** 或 **HERALD_TOTP_HMAC_KEYS**（JSON 密钥映射，支持轮换）。Stargate 须使用相同密钥对请求签名，并发送 `X-Timestamp`、`X-Service`、`X-Signature`（可选 `X-Key-Id`）。
- 不要将 API Key 或 HMAC 密钥写入日志或对外暴露。优先使用环境变量或密钥管理服务，避免将密钥写入并提交到仓库的配置文件中。

## 生产环境建议

- **网络**：将 herald-totp 部署在内网或私有网络中，仅允许 Stargate（或统一网关）访问；不要将 herald-totp 直接暴露到公网，除非在 HTTPS 与严格访问控制之后。
- **HTTPS**：若 herald-totp 会经过公网或不可信网络被访问，应在其前增加带 TLS 的反向代理（如 Traefik、nginx）。此时 Stargate 的 `HERALD_TOTP_BASE_URL` 应使用 `https://`。
- **最小权限**：使用非 root 用户运行进程；在 Docker 中尽量使用非 root 用户镜像。
- **Redis**：建议为 herald-totp 使用独立 Redis 实例或独立 DB 索引。启用 Redis 认证与 TLS（若可用）。不要将 Redis 暴露到公网。
- **日志**：避免记录可能包含 TOTP 码或恢复码的请求体或请求头；仅记录运维与排查所需字段（如 subject、result、reason）即可。

## 小结

- **HERALD_TOTP_ENCRYPTION_KEY**（32 字节）须严格保密，不写入代码或提交的配置。
- 生产环境建议配置 **API_KEY** 或 HMAC 用于服务间鉴权；Stargate 侧配置与之一致。
- 尽量在内网部署 herald-totp，对外暴露时使用 HTTPS 与访问控制。
- Redis 建议启用认证与 TLS。
