# 文档索引

欢迎查阅 herald-totp 的文档。herald-totp 是 [Herald](https://github.com/soulteary/herald) 与 [Stargate](https://github.com/soulteary/stargate) 的 TOTP 双因素认证服务。

## 多语言文档

- [English](../enUS/README.md) | [中文](README.md)

## 文档列表

### 核心文档

- **[README.zhCN.md](../../README.zhCN.md)** - 项目概述与快速开始

### 详细文档

- **[API.md](API.md)** - 完整 API 说明
  - Base URL 与鉴权（API Key / HMAC）
  - POST /v1/enroll/start、POST /v1/enroll/confirm
  - POST /v1/verify（TOTP 或恢复码）
  - GET /v1/status
  - GET /healthz
  - 错误码与 HTTP 状态码

- **[DEPLOYMENT.md](DEPLOYMENT.md)** - 部署指南
  - 二进制与 Docker 运行
  - 配置项说明（加密密钥、Redis、TOTP 参数、限流）
  - 与 Stargate 集成
  - 健康检查与监控

- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - 故障排查
  - 绑定/验证失败
  - 401 unauthorized
  - config_error（缺少加密密钥）
  - rate_limited、replay、expired
  - Redis 连接

- **[SECURITY.md](SECURITY.md)** - 安全实践
  - 加密密钥与 API Key / HMAC
  - 凭证存储
  - 生产环境建议

## 快速导航

### 新手入门

1. 阅读 [README.zhCN.md](../../README.zhCN.md) 了解项目
2. 查看 [快速开始](../../README.zhCN.md#快速开始)
3. 参考 [DEPLOYMENT.md](DEPLOYMENT.md) 进行配置与 Stargate 集成

### 开发人员

1. 查看 [API.md](API.md) 了解绑定/验证协议与错误码
2. 参考 [DEPLOYMENT.md](DEPLOYMENT.md) 了解部署方式

### 运维人员

1. 阅读 [DEPLOYMENT.md](DEPLOYMENT.md) 了解部署与 Stargate 侧配置
2. 参考 [SECURITY.md](SECURITY.md) 了解生产实践
3. 排查问题：[TROUBLESHOOTING.md](TROUBLESHOOTING.md)

## 文档结构

```
herald-totp/
├── README.md              # 项目主文档（英文）
├── README.zhCN.md         # 项目主文档（中文）
├── docs/
│   ├── enUS/
│   │   ├── README.md       # 文档索引（英文）
│   │   ├── API.md          # API 文档（英文）
│   │   ├── DEPLOYMENT.md   # 部署指南（英文）
│   │   ├── TROUBLESHOOTING.md # 故障排查（英文）
│   │   └── SECURITY.md     # 安全（英文）
│   └── zhCN/
│       ├── README.md       # 文档索引（中文，本文件）
│       ├── API.md          # API 文档（中文）
│       ├── DEPLOYMENT.md   # 部署指南（中文）
│       ├── TROUBLESHOOTING.md # 故障排查（中文）
│       └── SECURITY.md     # 安全（中文）
└── ...
```

## 按主题查找

- API 端点与鉴权：[API.md](API.md)
- 配置与 Stargate 集成：[DEPLOYMENT.md](DEPLOYMENT.md)
- 常见问题：[TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- 安全：[SECURITY.md](SECURITY.md)
