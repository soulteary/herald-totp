# 升级至 v2.0.0

服务与 Go SDK 一起升级到主版本 v2，根模块改为
`github.com/soulteary/herald-totp/v2`，SDK 导入路径为
`github.com/soulteary/herald-totp/v2/pkg/heraldtotp`。HTTP 路由继续使用 `/v1`，
不要将模块主版本、HMAC 协议版本和 HTTP 路由版本混为一谈。

从 v1.2.8 升级时，HMAC 调用端和服务端必须共同迁移至绑定请求方法、路径、查询、
密钥 ID、时间戳、服务名、随机值和请求体摘要的 v2 协议。旧签名不再接受，也没有
回退开关。Redis 原子消费随机值，存储故障返回 503；无效或不完整的 HMAC 请求
不会回退至 API key。同时配置两种凭据的 SDK 只发送 HMAC。服务名为 1–128
字节，显式密钥 ID 最多 128 字节，按 UTF-8 字节而非字符计算。配置和 SDK
分别在启动、签名前检查，签名失败不得发送请求。

POST 请求必须使用 JSON。SDK 拒绝认证请求的重定向，应配置最终服务地址和经过
验证的 TLS。单个映射密钥仍允许省略 ID，多个映射密钥必须显式选择。只使用
API key 的部署仍受支持，可独立升级服务和调用端，但同样须满足 JSON 和重定向要求。

升级前保留 Redis 数据集和原加密密钥，暂停 HMAC 调用端并排空在途操作。部署
`ghcr.io/soulteary/herald-totp:v2.0.0`，升级包括 Herald 代理在内的所有调用端，运行
`go get github.com/soulteary/herald-totp/v2@v2.0.0` 并修改导入路径，使用 v2 SDK
或 `heraldtotp.SignRequest`。完成正确签名、重放拒绝和目标变更拒绝检查后恢复流量。
不要混用旧 HMAC 客户端和新服务。现有 TOTP 密钥、凭据和恢复码记录格式不变，
不要求用户重新绑定；更早版本的 enrollment 索引升级限制仍适用，见安全指南。

回滚必须协调服务和调用端版本，单独回滚一侧会导致认证失败，恢复 v1.2.8 也会恢复
旧协议的请求绑定及重放风险。整个过程保留 Redis 和加密密钥，失败响应不代表写入
未提交。发布流程仅接受与 `/v2` 模块匹配的正式 `v2.x.y` 标签，不发布 RC；部署请
固定完整版本，避免依赖会变动的主版本或 `latest` 标签。
