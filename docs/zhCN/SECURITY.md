# herald-totp 安全实践

本文说明 herald-totp 的安全注意事项与推荐做法。

## 加密密钥

- **HERALD_TOTP_ENCRYPTION_KEY** 为必填项，须正好为 32 字节（256 位）以用于 AES-256-GCM；密钥无效时服务会拒绝启动。
- 请严格保密该密钥，不得提交到代码库。应通过环境变量或密钥管理服务（如 Kubernetes Secrets、HashiCorp Vault）注入。本地开发可使用 `.env`，并确保 `.env` 已加入 `.gitignore`。
- 轮换密钥时需注意：Redis 中已加密的 TOTP 密钥无法用新密钥解密。若需轮换，请规划迁移（用户重新绑定或解密后重新加密）。

## API Key 与 HMAC

- 配置 **API_KEY** 后，herald-totp 会要求所有受保护接口（enroll、verify、revoke、status）的请求头 `X-API-Key` 与之一致。请使用足够强且唯一的密钥并妥善保管。
- Stargate 侧需配置相同的 `HERALD_TOTP_API_KEY`，以便在请求 herald-totp 时携带该密钥。
- 也可使用 **HMAC_SECRET** 或 **HERALD_TOTP_HMAC_KEYS**（JSON 密钥映射，支持轮换）。Stargate 须使用相同密钥对请求签名并发送 `X-Timestamp`、`X-Service`、`X-Signature`；密钥映射包含多个密钥时必须发送 `X-Key-Id`，只有单一映射密钥时才可省略。
- 不要将 API Key 或 HMAC 密钥写入日志或对外暴露。优先使用环境变量或密钥管理服务，避免将密钥写入并提交到仓库的配置文件中。

## 生产环境建议

- **网络**：将 herald-totp 部署在内网或私有网络中，仅允许 Stargate（或统一网关）访问；不要将 herald-totp 直接暴露到公网，除非在 HTTPS 与严格访问控制之后。
- **HTTPS**：若 herald-totp 会经过公网或不可信网络被访问，应在其前增加带 TLS 的反向代理（如 Traefik、nginx）。此时 Stargate 的 `HERALD_TOTP_BASE_URL` 应使用 `https://`。
- **最小权限**：使用非 root 用户运行进程。官方容器已配置为数值用户和用户组 `10001:10001`。
- **Redis**：建议为 herald-totp 使用独立 Redis 实例或独立 DB 索引。启用 Redis 认证与 TLS（若可用）。不要将 Redis 暴露到公网。
- **日志**：避免记录可能包含 TOTP 码或恢复码的请求体或请求头；仅记录运维与排查所需字段（如 subject、result、reason）即可。
- **绑定响应**：生产环境不需要手动录入密钥时应设置 `EXPOSE_SECRET_IN_ENROLL=false`。`otpauth_uri` 本身仍包含密钥，必须按敏感数据处理。
- **指标接口**：`/metrics` 按设计不进行鉴权。应通过网络或反向代理限制访问，不得直接暴露到公网。

## 防重放

- 服务会原子认领容差窗口内实际匹配的 TOTP 计数器，既防止两个并发请求同时接受同一验证码，也防止未来窗口验证码在该窗口成为当前窗口后再次使用。
- 恢复码通过 Redis 乐观事务更新，同一恢复码在并发请求中只会被一个请求成功消费。
- 非空 `challenge_id` 使用 Redis `SET NX` 原子认领；重复使用会返回 `replay`。
- 防重放保证依赖 Redis 的可用性和一致性。不要将同一用户的 TOTP 请求分散到彼此独立的 Redis 数据集。
- 绑定确认会在同一个 Redis 事务中提交凭证、恢复码哈希并消费临时绑定记录；解绑会原子删除凭证和恢复码。
- 限流计数器保留窗口首次请求建立的过期时间，后续请求不会无限延长已被限制的计数器。

## 小结

- **HERALD_TOTP_ENCRYPTION_KEY**（32 字节）须严格保密，不写入代码或提交的配置。
- 生产环境建议配置 **API_KEY** 或 HMAC 用于服务间鉴权；Stargate 侧配置与之一致。
- 尽量在内网部署 herald-totp，对外暴露时使用 HTTPS 与访问控制。
- Redis 建议启用认证与 TLS。
