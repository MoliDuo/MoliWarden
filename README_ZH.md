# MoliWarden

运行在 **Vercel** 上的 Bitwarden 兼容服务端，自带 Web 密码库：

- 数据库：**PostgreSQL**（推荐 Neon，通过 Vercel Marketplace 一键接入）
- 附件 / Send 文件：**任意 S3 兼容存储**（AWS S3、Cloudflare R2 的 S3 接口、Backblaze B2、MinIO 等）
- **组织（共享）**：组织、成员、集合、集合级权限，官方客户端和自带 Web 密码库都能使用

> 本项目与 Bitwarden 官方无关，仅供学习交流。请定期备份。

---

## 功能

| 功能 | 状态 | 说明 |
|---|---|---|
| 密码库、TOTP、Passkey 登录、两步验证、设备管理、登录请求 | ✅ | |
| 附件 / Send | ✅ | 经官方客户端上传的单个文件上限约 **4.4 MB**（Vercel 请求体限制，见下文） |
| 实例备份（本地 / WebDAV / S3） | ✅ | 包含组织数据 |
| **组织 / 集合 / 成员角色** | ✅ | 所有者、管理员、经理、用户；只读 / 隐藏密码 / 可编辑 / 可管理 |
| 实时推送（WebSocket） | ⚠️ | Vercel 无法保持长连接。桌面端和浏览器扩展靠定期同步；移动端仍可走 Bitwarden 官方推送中继 |
| 邮件（邮箱两步验证、邀请邮件等） | ❌ | 邀请改为：被邀请人在 Web 密码库的“组织”页面接受 |
| 群组、策略、SSO、紧急访问 | ❌ | 未实现 |

### 组织共享的使用流程

1. 在 Web 密码库左侧点 **组织** → **新建组织**（浏览器本地生成组织密钥，服务器只保存加密后的密钥）。
2. **邀请成员**：填写对方的注册邮箱，选择角色和集合权限。对方必须已在本实例注册。
3. 被邀请人打开自己的 **组织** 页面，点击 **接受**。
4. 管理员点 **确认**，并与对方核对**指纹短语**一致后再确认。此时组织密钥用对方的公钥加密后交给对方。
5. 在密码库新建条目时选择归属组织和集合；已有的个人条目可以在详情页点 **移动到组织**。

官方客户端（桌面、浏览器扩展、手机）同步后会显示组织条目，也能直接新建或编辑组织条目。组织和成员的管理只能在自带的 Web 密码库里进行。

---

## 部署到 Vercel

### 1. 准备

- **PostgreSQL**：在 Vercel 项目的 *Storage → Marketplace* 里添加 **Neon**，它会自动注入 `DATABASE_URL`。也可以用任何 Postgres，自己设置 `DATABASE_URL`。
- **S3 兼容存储**：新建一个私有 bucket 和一对只对这个 bucket 有读写权限的 Access Key。

### 2. 导入项目

把本仓库推到你的 GitHub，然后在 Vercel 中 *Add New → Project* 导入。`vercel.json` 已经配置好构建命令（`npm run build:vercel`），Framework Preset 保持 *Other* 即可。

### 3. 环境变量

| 变量 | 必填 | 说明 |
|---|---|---|
| `DATABASE_URL` | ✅ | Postgres 连接串（Neon 集成会自动设置；也支持 `POSTGRES_URL`） |
| `JWT_SECRET` | ✅ | 至少 32 位的随机字符串，如 `openssl rand -base64 48`；用于签发登录令牌，更换后所有设备需要重新登录 |
| `ENCRYPTION_KEY` | ✅ | 至少 32 位的随机字符串，不要与 `JWT_SECRET` 相同；用于加密服务端保存的两步登录密钥、恢复码、API Key 和备份凭据。**请妥善保管**，更换后这些数据将无法解密 |
| `SHOW_PASSWORD_HINT` | | 设为 `1` 在登录页提供密码提示；默认关闭，因为知道邮箱的人都能看到提示 |
| `S3_ENDPOINT` | ✅ | 例如 `https://<account>.r2.cloudflarestorage.com`、`https://s3.us-east-1.amazonaws.com` |
| `S3_BUCKET` | ✅ | bucket 名称 |
| `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` | ✅ | 访问密钥 |
| `S3_REGION` | | 默认 `auto`（R2）；AWS 需填实际区域 |
| `S3_FORCE_PATH_STYLE` | | 默认路径风格；设为 `0` 改用虚拟主机风格 |
| `CRON_SECRET` | 推荐 | Vercel Cron 调用定时备份时的鉴权密钥（Vercel 会自动带上） |
| `MOLIWARDEN_CRON_SCHEDULE` | | 构建时生效的定时任务表达式，默认每天一次（Hobby 套餐只允许每天一次） |
| `BACKUP_ALLOW_PRIVATE_HOSTS` | | 设为 `1` 允许备份目的地使用内网或回环地址（自建 NAS、测试） |
| `PUSH_RELAY_DISABLED` | | 设为 `1` 不向 Bitwarden 官方推送中继注册 |
| `HIDE_WEB_VAULT` | | 构建时设为 `1`，则不发布 Web 密码库，只保留客户端 API |
| `WEBAUTHN_RP_ID` / `WEBAUTHN_RP_NAME` | | Passkey 的 RP ID 和显示名称，默认取站点域名和 `MoliWarden` |

### 4. 首次使用

部署完成后打开站点。**第一个注册的账号自动成为实例管理员**，之后的用户需要管理员在“用户管理”里生成邀请码才能注册。数据库表会在第一次请求时自动创建。

### 5. S3 的 CORS（可选）

超过 4 MB 的附件下载会被重定向到 S3 预签名链接。如果要在 **Web 密码库或浏览器扩展**里下载大附件，需要给 bucket 配置 CORS，允许你的站点域名和 `chrome-extension://*` 发起 `GET` 请求。官方桌面端和手机端不需要。

---

## Vercel 平台限制

- **上传大小**：Vercel Functions 的请求体上限是 4.5 MB，而官方客户端上传附件必须经过服务器，所以单个附件 / Send 文件最大约 4.4 MB。下载不受影响。
- **实时同步**：没有 WebSocket。其他设备上的改动不会立即出现，客户端会在解锁、定时同步或手动同步时拉取。
- **定时备份**：由 Vercel Cron 触发 `/api/internal/cron`。Hobby 套餐每天一次，Pro 可以通过 `MOLIWARDEN_CRON_SCHEDULE` 调得更频繁。
- **实例备份导入**：通过网页上传的备份文件同样受 4.5 MB 限制（网页会直接提示），大备份请用 WebDAV / S3 远程备份恢复。
- **导入密码库**：自带 Web 密码库导入大文件时会自动分批上传，不受 4.5 MB 限制；官方 CLI 的 `bw import` 是一次性上传，超过约 4.5 MB（大约两三千条）会失败，可拆分文件或改用 Web 密码库导入。
- **同步**：响应以流式返回，大密码库的同步不受 4.5 MB 限制。
- **地区**：Vercel 函数默认在 `iad1`（美国东部）。Neon 数据库请选同一地区，或在 Vercel 项目设置里把函数地区改到数据库附近，否则每次请求都要跨洋访问数据库。

### 部署后的排错

- 页面提示 `Server configuration error: DATABASE_URL is not configured`：没有设置数据库变量。
- 提示 `Database unavailable. Check DATABASE_URL`：连接串错误或数据库不可达，具体原因在 Vercel 的函数日志里。
- 页面显示密钥配置提示，或请求报 `JWT_SECRET is not set or too weak` / `ENCRYPTION_KEY is not set or too weak`：设置对应变量（至少 32 位）后重新部署。
- 报错 `a stored secret cannot be decrypted. Was ENCRYPTION_KEY changed?`：`ENCRYPTION_KEY` 与写入数据时的不一致，改回原来的值。
- 上传附件提示 `File storage is not configured`：缺少 `S3_*` 变量。
- 修改环境变量后需要在 Vercel 里 **Redeploy** 才会生效。

---

## 本地开发与测试

```bash
npm install
```

启动测试用的 Postgres、S3（SeaweedFS）和 PgBouncer（事务池模式，模拟 Neon 的 pooled 连接串）：

```bash
npm run test:services
```

新建 `.env.local`（参考上面的环境变量），然后：

```bash
npm run build
```

```bash
set -a; . ./.env.local; set +a; npm run dev:server
```

跑全部测试（类型检查、i18n、单元测试、SQL 检查、端到端测试、Vercel 构建产物冒烟测试）：

```bash
npm test
```

各部分也可以单独跑：

| 命令 | 内容 |
|---|---|
| `npm run test:e2e` | 接口端到端测试：账号、密码库、附件、Send、备份、组织权限和安全回归、配置缺失时的报错、Web 导入分批。每个文件会重置 `public` schema，请使用专用测试库 |
| `npm run test:official-cli` | 用官方 Bitwarden CLI（`bw`，首次运行自动下载到 `~/.cache/moliwarden-bw-cli`，不进依赖）走一遍：密码 / API Key 登录、锁定解锁、条目、文件夹、附件、Send、导出、确认组织成员、共享和集合权限。约 5 分钟 |
| `npm run test:ui` | 用浏览器（Playwright，默认在官方 Docker 镜像里运行）把 Web 密码库的主要页面和流程点一遍，包括条目、文件夹、回收站、附件、Send、导入导出、设置、管理员、组织共享全流程、中文界面和 375px 手机宽度；任何页面报错、控制台错误、错误提示或 5xx 都算失败。见 `tests/ui/README.md` |
| `npm run test:smoke` | 构建 `.vercel/output`，复制到仓库外，用 `tests/vercel-emulator.ts` 按 Vercel 的路由规则、4.5 MB 请求体限制、`waitUntil` 和 Cron 调用方式运行 |
| `scripts/vercel-build-local.sh` | 不需要 Vercel 账号，用官方 `vercel build` 生成与线上一致的产物（会执行 `npm ci`）|

要验证 Neon 连接池模式，把 `TEST_DATABASE_URL` 指向 PgBouncer 再跑端到端测试：

```bash
TEST_DATABASE_URL=postgres://mw:mw@localhost:56432/mw npm run test:e2e
```

GitHub Actions（`.github/workflows/ci.yml`）在每次推送时运行以上全部内容。

---

## 架构说明

- `src/main/app.ts`：Hono 应用，挂载 `src/modules/*/routes.ts`；每个模块分为 routes（HTTP）、service（领域逻辑）和 repo（Kysely 查询）。
- `src/platform/db/migrations/`：数据库结构，由服务端在首个请求时按顺序执行，也可用 `npm run db:migrate` 手动执行。
- `scripts/build-vercel.ts`：生成 Vercel Build Output（静态 Web 密码库 + 单个 Node 函数 + 路由 + Cron）。
- `src/modules/organizations/access.ts`：组织权限的唯一判定点。只有**已确认**的成员才能访问组织数据；被撤销、仅邀请或仅接受的成员没有任何访问权限。
- 条目归属：个人条目 `user_id` 非空，组织条目 `organization_id` 非空，二者由数据库 CHECK 约束保证互斥；文件夹、收藏、归档按用户存放在 `cipher_user_state`。

## 许可

LGPL-3.0，见 [LICENSE](./LICENSE) 和 [NOTICE](./NOTICE)。
