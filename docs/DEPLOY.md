# 部署教程

从零把收款系统跑起来。三种部署形态，按你的情况选一种。

---

## 先搞清楚：现在有两个程序

上一版只有一个 `wxpayclient.exe`。现在拆成了两个：

| 程序 | 跑在哪 | 干什么 |
|---|---|---|
| **`wxpayclient.exe`（网关）** | 任意系统，通常放在能上外网的服务器 | 队列、签名上报上游、网页面板、代理管理 |
| **`wxpayagent.exe`（代理）** | **必须**在装微信的那台 Windows 上 | 注入 `wxhook.dll`、接住到账、转发给网关 |

**为什么要拆**：微信只能装在 Windows 上，而网关需要一个稳定、能上外网、不容易关机的地方（服务器）。
代理只管"抓到就转发"，业务全在网关，所以微信那台机器关机重启，网关仍然正常上报。

> ⚠️ **关键约束：两个程序都要 `127.0.0.1:29731`。**
> 因为 `wxhook.dll` 里把投递地址写死成这个端口。
> **它们不能跑在同一台 Windows 上**（除非你改 DLL 重编）。
> 同机部署请直接只用网关——见下面的「形态 A」。

---

## 形态 A：单机部署（最简单）

适合：微信和网关都在同一台电脑，不关机，能上外网。

```
Weixin.exe ──注入──> wxhook.dll ──POST──> wxpayclient.exe(29731) ──> 上游收款站
                                          └─ 面板也在这个端口
```

### 步骤

**1. 准备工具链**

```powershell
winget install --id GoLang.Go
winget install --id MartinStorsjo.LLVM-MinGW.UCRT `
  --accept-package-agreements --accept-source-agreements
```

**2. 编译**

```powershell
cd wxpay-client

# 两个 DLL（Go 部分只编网关时其实不需要，但 wxhook.dll 必须有）
powershell -ExecutionPolicy Bypass -File scripts\build.ps1

# 网关
go build -o build\wxpayclient.exe .\cmd\gateway
```

产物：`build\wxpayclient.exe`、`build\wxhook.dll`、`build\wxinject.dll`

**3. 首次启动**

```powershell
cd build
.\wxpayclient.exe
```

首次会在 `build\data\` 生成 `config.json`。启动日志应看到：

```
[http] 面板监听 http://127.0.0.1:29731
[auth] 面板未设置密码：只允许本机直连访问
```

**4. 打开面板填上游**

浏览器访问 `http://127.0.0.1:29731/` → 「设置」：

| 字段 | 填什么 |
|---|---|
| 地址 | 你的收款站，如 `https://pay.example.com` |
| 商户 ID | 上游给你的，必填 |
| 商户密钥 | 上游给你，保存后用 DPAPI 加密存在本地 |
| 监听地址 | 保持 `127.0.0.1:29731` |

点「保存」，再点「测试连接」——出现「连接正常」说明密钥对上了。

**5. 注入微信**

面板右上角「注入微信」（或「微信账号」页）。

**必须以管理员身份运行 `wxpayclient.exe`**，否则读不到微信进程。

注入成功后「微信账号」页应显示：
- 微信程序路径
- 微信版本（如 `4.1.12.53`）
- 进程 PID
- Hook 状态：`已注入`

> 状态一直是 `Weixin.dll 未加载`？说明注到了微信的子进程。
> 微信 4.x 有多个 `Weixin.exe`，只有加载了 `Weixin.dll` 的那个有效，通常内存占用最大。
> 面板会列出所有进程，按 PID 注入正确的那个。

**6. 验证收款**

在「微信账号」页点「绑定通道 ID」，填上游分配的通道号。
然后用微信收一笔小额款，观察：
- 「概览」的「识别收款」+1
- 「收款记录」出现一条，状态 `done`

---

## 形态 B：分离部署（推荐用于生产）

适合：微信在办公室 Windows 电脑，网关在服务器。

```
办公室 Windows                          服务器 Linux
┌────────────────────┐                 ┌──────────────────┐
│ Weixin.exe          │                 │ wxpayclient       │
│   ↓ 注入            │    HTTPS        │  :443 / :29731    │
│ wxhook.dll          │ ──────────────> │                   │
│   ↓ POST 29731      │   Bearer token  │  └→ 上游收款站     │
│ wxpayagent.exe      │                 │  └→ 网页面板       │
│   :29731 收事件      │                 │                   │
└────────────────────┘                 └──────────────────┘
```

### 2.1 服务器：部署网关

**编译**（在服务器上，或本地交叉编译后上传）

```bash
# Linux 服务器上直接编
GOOS=linux GOARCH=amd64 go build -o wxpayclient ./cmd/gateway

# 或从 Windows 交叉编译
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -o wxpayclient ./cmd/gateway
```

**放到 `/opt/wxpay/`，设置密码**

```bash
cd /opt/wxpay
./wxpayclient passwd
# 新的面板密码（至少 8 位，输入时会回显）：********
# 再输一遍：********
# 面板密码已保存。正在运行的网关需要重启才会读到新密码。
```

> 密码存成 `pbkdf2-sha256$210000$salt$hash`，**不是明文**。
> 忘了密码就重新执行 `passwd`，旧密码立即失效。

**生成代理接入令牌**

```bash
./wxpayclient agent-token
# 新的代理接入令牌（只显示这一次，旧令牌已作废；网关需要重启才会读到）：
# wxa_o48mWQCJ6lbc7_4hTPL9g6sVvSjfXM1n
```

> **明文只显示这一次**，网关只存 SHA-256。
> 丢了就重新生成（旧令牌立刻作废，所有代理都要改）。

**启动，监听所有网卡**

```bash
./wxpayclient -data /var/lib/wxpay -listen 0.0.0.0:29731
```

或写进 systemd `/etc/systemd/system/wxpay.service`：

```ini
[Unit]
Description=微信收款网关
After=network-online.target

[Service]
Type=simple
User=wxpay
WorkingDirectory=/opt/wxpay
ExecStart=/opt/wxpay/wxpayclient -data /var/lib/wxpay -listen 0.0.0.0:29731
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /sbin/nologin wxpay
sudo mkdir -p /var/lib/wxpay && sudo chown wxpay:wxpay /var/lib/wxpay
sudo systemctl enable --now wxpay
sudo systemctl status wxpay
```

**防火墙**

```bash
# 只开 29731（或你反代用的 443）
sudo ufw allow 29731/tcp

# 若用 Nginx 反代，不要直接暴露 29731
```

**Nginx 反代 + HTTPS**（推荐，令牌走明文 HTTP 不安全）

```nginx
server {
    listen 443 ssl http2;
    server_name pay-gw.example.com;

    ssl_certificate     /etc/letsencrypt/live/pay-gw.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/pay-gw.example.com/privkey.pem;

    client_max_body_size 2m;

    location / {
        proxy_pass http://127.0.0.1:29731;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

> 网关会检测 `X-Forwarded-For` / `X-Real-IP` 等头。
> **只要出现这些头，就不认为是"本机直连"**，必须登录。
> 这是防止反代把外部请求伪装成本机。

### 2.2 Windows 电脑：部署代理

**编译**

```powershell
cd wxpay-client
powershell -ExecutionPolicy Bypass -File scripts\build.ps1   # 出两个 DLL
go build -o build\wxpayagent.exe .\cmd\agent
```

需要拷到 Windows 机器上的文件：

```
wxpayagent.exe
wxhook.dll          ← 必须和 exe 同目录
wxinject.dll
```

**首次启动，带参数**

```powershell
.\wxpayagent.exe -gateway https://pay-gw.example.com -token wxa_o48mWQCJ6lbc7_4hTPL9g6sVvSjfXM1n -id office-pc
```

| 参数 | 说明 |
|---|---|
| `-gateway` | 网关地址。反代就用 `https://`，直连就 `http://IP:29731` |
| `-token` | 上面生成的 `wxa_...` 令牌 |
| `-id` | 代理名称，默认用计算机名。多台机器时要能区分 |

参数会写进 `data\agent.json`，**令牌用 DPAPI 加密**（明文不落盘）。
以后直接双击 `wxpayagent.exe` 即可，不用再带参数。

启动成功应看到：

```
[config] ...\data\agent.json | 网关 https://pay-gw.example.com | 代理名 office-pc
[http] 接收 wxhook 投递：http://127.0.0.1:29731/hook/payment
```

**以管理员身份运行**（注入微信需要）。

**验证连接**

网关面板「代理」页应出现 `office-pc`，状态「在线」，
并显示微信版本、Hook 状态、积压数。

> 代理每 5 秒心跳一次，超过 **30 秒**没心跳算离线。

**设开机自启**

用任务计划程序（`taskschd.msc`）：

| 项 | 值 |
|---|---|
| 触发器 | 登录时 |
| 操作 | 启动 `wxpayagent.exe` |
| 勾选 | 「使用最高权限运行」 |
| 起始于 | 程序所在目录 |

---

## 形态 C：只用代理，不装网关

不推荐。网关负责队列、重试、签名、去重，跳过它等于把这些都丢了。

如果只是临时测试，可以：

```powershell
.\wxpayagent.exe -gateway http://127.0.0.1:29800 -token xxx
```

但 29800 上没有网关时，代理会一直重试、积压在本地 outbox。

---

## 部署后必做的验证

### 1. 面板能登录

```powershell
# 未登录应该 401
curl http://127.0.0.1:29731/api/snapshot
# {"error":"需要登录"}

# 登录拿 cookie
curl -c cookie.txt -X POST http://127.0.0.1:29731/api/auth/login `
  -H "Content-Type: application/json" -d '{\"password\":\"你的密码\"}'
# {"ok":true}

curl -b cookie.txt http://127.0.0.1:29731/api/snapshot
# 完整的 snapshot JSON
```

### 2. 上游连接正常

面板「概览」→「测试连接」，或：

```powershell
curl -b cookie.txt http://127.0.0.1:29731/api/selftest
```

看 `tokenOk` 是否为 `true`。

> 这个接口**最长要等 33 秒**——上游匹配成功时会同步等它回调商户。
> 超时给 60 秒。

### 3. 代理在线

```powershell
curl -b cookie.txt http://127.0.0.1:29731/api/agents
```

`online` 应为 `true`，`injectorOk` 应为 `true`（Windows 上装着 DLL）。

### 4. 端到端收一笔

用微信收 0.01 元，然后：

```powershell
curl -b cookie.txt "http://127.0.0.1:29731/api/queue?limit=5"
```

应看到一条 `state: "done"`。

### 5. 断网演练（建议做一次）

这一步验证"网关挂了不丢单"，是分离部署最重要的保障。

1. 停掉网关（`systemctl stop wxpay`）
2. 用微信收一笔
3. 看代理日志：

```
[hook]    收到收款 amount=1.23 msgId=...，已存入 outbox #1
[forward] #1 第 1 次转发失败：... connectex: No connection could be made ...
```

4. 启动网关，等 10~30 秒：

```
[heartbeat] 已恢复与网关的连接
[forward]   #1 已送达网关 amount=1.23
```

5. 网关面板「收款记录」应出现这笔，状态最终变成 `done`

> 这就是代理存在的意义：微信到账那一刻即使网关不可用，
> 事件也先落在代理本地 `outbox.db`，网关恢复后自动补发。

---

## 常见问题

### 两个程序都想用 29731

**这是设计如此。** `wxhook.dll` 写死投递到 `127.0.0.1:29731`。

- 同机部署 → **只用网关**，不需要代理
- 分离部署 → 网关在服务器（另一个操作系统），不冲突

在 Windows 上同时跑两个，代理会启动失败：

```
启动失败: 监听 127.0.0.1:29731 失败（wxhook.dll 固定投递到这里，端口不能换；
若本机已在跑网关 wxpayclient.exe，同机部署不需要代理，关掉其中一个）
```

### 端口被占

网关会自动顺延到 29732、29733…，实际地址在启动日志和面板左下角。

**代理不会顺延**——它必须占 29731。被占了就关掉占用者。

```powershell
Get-NetTCPConnection -LocalPort 29731 -State Listen |
  ForEach-Object { Get-Process -Id $_.OwningProcess }
```

### 面板打不开 / 提示需要登录但没设过密码

没设密码时**只允许本机直连**。如果你从别的机器访问，必须：

1. 先 `wxpayclient passwd` 设密码
2. 重启网关

### 代理一直显示离线

```powershell
# 看代理日志，最快
Get-Content data\logs\agent.log -Tail 20
```

常见：
- `网关拒绝了接入令牌` → 令牌错了，或网关重新生成过令牌
- `连不上网关` → 地址写错 / 防火墙 / HTTPS 证书问题
- `解不开 agent.json 里的令牌` → 换了 Windows 用户或机器，用 `-token` 重新填

### 注入失败

按这个顺序查：

| 现象 | 原因 |
|---|---|
| `需要管理员权限` | 没用管理员运行 |
| `找不到微信` | 微信没启动，或装在非标准路径 |
| `bitness mismatch` | 微信和 DLL 位数不一致，都用 x64 |
| `特征扫描未命中` | 微信版本不支持，见 `docs/HOOK.md` 补特征码 |
| 注入成功但状态 `未注入` | 注到了没有 `Weixin.dll` 的子进程 |

### 密钥/令牌丢了

| 丢的是什么 | 怎么恢复 |
|---|---|
| 面板密码 | `wxpayclient passwd` 重设 |
| 代理令牌 | `wxpayclient agent-token` 重新生成，然后每台代理重新填 `-token` |
| 上游商户密钥 | 面板「设置」重新填（DPAPI 密文换机器解不开，必须重填） |

---

## 数据与备份

| 文件 | 内容 | 要不要备份 |
|---|---|---|
| `data/config.json` | 网关配置（密钥是密文） | ✅ |
| `data/secret.key` | **Linux 网关的主密钥**，丢了 config 里的密文就废了 | ✅ 与 config 一起 |
| `data/queue.db` | 收款队列 + 事件日志 | ✅ |
| `data/account_channels.json` | 账号→通道绑定 | ✅ |
| `data/payment_codes.json` | 固定金额收款项 | ✅ |
| `data/logs/` | 运行日志 | 建议 |
| `data/agent.json` | 代理配置（令牌 DPAPI 密文） | ✅ |
| `agent` 侧的 `data/outbox.db` | 代理本地积压（网关不通时暂存） | 一般不用 |

**`config.json` 和 `agent.json` 里的密文绑定机器**，备份到另一台解不开。

密钥保护按平台分两套，目的都是**防配置文件外流**（配置常被备份、拷贝、贴进工单）：

| 平台 | 加密方式 | 密文前缀 | 解开需要 |
|---|---|---|---|
| Windows（代理） | DPAPI，绑定当前用户 | `enc:v1:` | 同一 Windows 用户 |
| Linux（网关） | AES-256-GCM | `enc:fk1:` | `data/secret.key`（0600） |

Linux 上**密钥和密文分开存**：`config.json` 里是 `enc:fk1:...`，
真正的主密钥在 `data/secret.key`。单独泄露任何一个文件都拿不到密钥。

```bash
# 必须收紧权限，网关会自动生成这个文件
chmod 600 /var/lib/wxpay/config.json /var/lib/wxpay/secret.key
```

> 备份时 `secret.key` **必须和 `config.json` 一起走**，否则恢复后密钥解不开。
> 但也不要把它和配置放进同一个网盘目录——那就失去分开存的意义了。

恢复后如果两个文件对不上（比如只恢复了 config），面板会报密钥解不开，
重新在「设置」里填一次即可。

---

## 升级

```bash
git pull

# 网关
go build -o wxpayclient ./cmd/gateway
sudo systemctl restart wxpay

# 代理（Windows）
powershell -File scripts\build.ps1
go build -o build\wxpayagent.exe .\cmd\agent
# 关掉旧进程，替换 exe，重新启动
```

**数据库自动迁移**，不用手工改表。旧配置里的 `19089` 会被自动认成 `29731`。

---

## 安全清单

上线前逐条确认：

- [ ] 面板密码已设置（`wxpayclient passwd`）
- [ ] 对外暴露走 HTTPS（Nginx 反代），不用明文 HTTP
- [ ] 代理令牌已生成，且只在代理机器的 `agent.json` 里
- [ ] `config.json` 权限 600（Linux）
- [ ] 上游 `merchantSecret` 已填，且「测试连接」通过
- [ ] 防火墙只开必要端口
- [ ] 备份了 `data/` 目录

---

## 架构速查

```
微信服务器
   │ 收款到账
   ▼
Weixin.exe ──[wxhook.dll 注入]──> 抓到 appmsg XML
   │
   ▼ POST 127.0.0.1:29731/hook/payment
wxpayagent.exe（Windows，需管理员）
   │ ① 落本地 outbox（SQLite，网关不通不丢单）
   │ ② 带 Bearer 令牌转发
   ▼ POST /api/agent/events
wxpayclient.exe（服务器）
   │ ③ 两级去重（msgId → source_key）
   │ ④ 队列 (SQLite)
   │ ⑤ HMAC-SHA256 签名
   ▼ POST /api/report
上游收款站
```

**相关文档**

| 文件 | 内容 |
|---|---|
| `docs/HOOK.md` | 注入原理、特征码、版本支持、补特征码流程 |
| `docs/PROTOCOL.md` | 端到端协议、去重设计、重试矩阵 |
| `docs/UI.md` | 面板使用手册 |
| `docs/WEBHANDOFF.md` | 给网页端开发者 |
