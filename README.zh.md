# relay-preflight

**中转/聚合 API 配置的离线卫生检查。** 在提交含第三方 OpenAI 兼容中转密钥的
`.mcp.json`、Claude `settings.json`、`.env` 或 shell 片段之前，本工具标出：内联明文
`sk-...` 密钥、明文 `Bearer` 令牌、明文 `http://` base_url、以及只有密钥引用却无端点。
它对每个密钥脱敏，把 URL 裁剪到 `host:port`，绝不读取环境变量值，也不发起任何网络请求。

纯 Python 标准库，离线，Windows / macOS / Linux，Python 3.10+。

## 为什么存在

中转/聚合配置容易犯两个错：把 `sk-...` 直接粘进会提交的配置，或把密钥指向明文
`http://`。通用扫描器（gitleaks、trufflehog、detect-secrets）也能扫描指定文件和目录，
但它们面向仓库/pre-commit 代码扫描且需要安装；本工具面向非开发者填写中转配置的那一刻，
零安装，带中转专属规则（公开明文 `http://` base_url、无端点的 env 引用、命令行内联
Bearer），输出脱敏，不读 env 值，不做密钥校验流量。它**不**判断上游模型是否真实——
那需要单独的探测工具。

## 安装

无需编译，无需依赖。

- Claude Code：`claude --plugin-dir ./relay-preflight`，或在
  `.claude-plugin/marketplace.json` 注册本地市场。
- 便携 skill（Codex/Cursor/Gemini CLI/Roo Code）：把 `skills/relay-preflight/`
  复制到客户端的 skills 目录。

## 用法

```bash
python skills/relay-preflight/scripts/relay_preflight.py .mcp.json settings.json .env [--json] [--output report.md]
```

### 退出码

| 码 | 含义 |
|---|---|
| 0 | 干净 |
| 2 | 警告（引用无端点、二进制跳过） |
| 3 | 失败（内联密钥、Bearer 明文、http URL） |
| 1 | 用法 / IO 错误 |

### 规则

| 规则 | 触发条件 | 级别 |
|---|---|---|
| inline-secret | 文件内明文 `sk-...`（含 `sk-ant-`）、`pk-live/pk-test-...` 或紧凑 JWT（`eyJ...`）（`.json` 标注 JSON 路径） | FAIL |
| bearer-literal | 命令/参数行内联 `Authorization: Bearer <token>` | FAIL |
| plaintext-url | 公开 `http://` 端点（base_url 字段，或携带密钥/env 引用的 URL） | FAIL |
| local-plaintext-url | localhost/127.0.0.1/::1 上的 `http://`（不出本机） | WARN |
| bind-all-plaintext-url | `0.0.0.0` 上的 `http://`（绑定所有网卡，非环回，可被外网访问） | WARN |
| nonendpoint-http | 无密钥/端点上下文的公开 `http://` 链接（文档链接、示例） | WARN |
| no-base-url | 所有扫描文件中都有 `${VAR}` 引用却无端点 | WARN |

## 相关工作

- [gitleaks](https://github.com/gitleaks/gitleaks)、
  [trufflehog](https://github.com/trufflesecurity/trufflehog)、
  [detect-secrets](https://github.com/Yelp/detect-secrets) 都接受显式文件/目录
  （不只扫 git 历史）；trufflehog 还会在线校验密钥。它们面向仓库/pre-commit 代码扫描
  且需要安装。本工具差异在于：面向非开发者写配置那一刻、零安装、中转专属规则
  （明文 `http://` base_url、无端点 env 引用、命令行内联 Bearer）、每个密钥脱敏、
  不读 env 值、永不联网。
- 真实性判断（该端点是否真是宣称的模型）不在本工具范围，属于单独的行为探测。

## 测试

```bash
python -m pytest tests/ -q
```

39 个测试，仅标准库；人工谓词变异抽查（翻转 http/https 闸门会使明文测试变红；
记录在 CHANGELOG）。

## 限制（诚实披露）

- 仅卫生检查：不做真实性探测、不校验密钥、不检查可达性。
- 只扫描作为参数传入的文件，不扫整盘。`no-base-url` 在所有传入文件间聚合判定，
  因此密钥在 A、端点在 B 不再误报。
- 不读 env 值；基于模式。已覆盖：`sk-`（含 `sk-ant-`）、`pk-live/pk-test-`、
  紧凑三段 JWT（`eyJ...`）、内联 Bearer。其他形式——非紧凑 JWT、自定义前缀、
  无已知前缀的 API key——可能漏检；视为兜底，不是审计。

## 许可证

MIT，© 2026 Daizhi Liao (dafahaha)。
