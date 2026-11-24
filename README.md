# wxhook

Windows 便携程序：抓取微信收款到账，自动上报到 Linux 收款站。

配套服务端：[leoch627/ezpay](https://github.com/leoch627/ezpay)

---

## 它做什么

```
Weixin.exe
   │ 收款到账时 printpb 被调用，参数带 appmsg XML
   ▼
wxhook.dll  ← 本程序注入
   │ 汇编跳板快照寄存器（不改栈、不改 ABI）
   │ 找到 XML → 解析金额 / 单号 / 商户号
   │ POST 127.0.0.1:29731/hook/payment
   ▼
wxhook.exe  ← 本程序主体
   │ 落本地 outbox.db（断网不丢）
   │ HMAC-SHA256 签名
   │ POST https://你的收款站/api/report
   ▼
Linux 收款站：按金额匹配订单 → 回调商户
```

**只做两件事**：抓、报。所有业务逻辑（订单、匹配、对账、后台）都在 Linux 那边。

---

## 文件

```
wxhook/
├── hook/
│   ├── include/          ABI 头（C++/Go 共用）
│   ├── src/              注入组件源码
│   └── tests/            真实样本回归
├── internal/
│   ├── inject/           wxinject.dll 绑定（纯 syscall，无 cgo）
│   ├── outbox/           本地队列（SQLite）
│   ├── secret/           DPAPI（Windows）/ AES-GCM（Linux 调试）
│   ├── version/          读微信 PE 版本资源
│   └── auth/ version/ model/
├── cmd/agent/            → wxhook.exe
├── scripts/
│   └── build.ps1         编译 DLL
└── docs/                 HOOK 原理、协议、特征码提取
```

---

## 编译

依赖：

```powershell
winget install --id GoLang.Go
winget install --id MartinStorsjo.LLVM-MinGW.UCRT `
  --accept-package-agreements --accept-source-agreements
```

```powershell
# 1) 两个 DLL
powershell -ExecutionPolicy Bypass -File scripts\build.ps1

# 2) 主程序
go build -o build\wxhook.exe .\cmd\agent
```

产物（拷到一个目录就是绿色版）：

```
wxhook.exe        15 MB
wxhook.dll       834 KB
wxinject.dll     742 KB
```

---

## 首次运行

```powershell
# 管理员 PowerShell
cd <程序目录>
.\wxhook.exe -server https://pay.example.com -token RT-xxxxxxxx
```

| 参数 | 说明 |
|---|---|
| `-server` | Linux 收款站地址 |
| `-token` | 收款站的 `reportToken`（服务器 `config.json` 里那个） |
| `-id` | 挂机点名称，默认计算机名 |
| `-data` | 数据目录，默认程序目录下的 `data\` |

参数写进 `data\agent.json`，**令牌用 DPAPI 加密**（不落明文）。
以后直接双击 `wxhook.exe` 即可。

---

## 本地面板

```
http://127.0.0.1:29732/
```

能看到：

- 微信版本、路径、是否运行、PID
- **当前收款账号**（wxid）
- Hook 状态（已安装 / 特征未命中 / 版本不支持…）
- 捕获/识别计数、上报成功/失败、去重丢弃
- 本地队列积压
- 实时日志（可按错误/警告过滤）

能改：

- 收款站地址
- 上报密钥
- 挂机点名称

还能手动注入指定进程、列出所有微信进程（标出哪个加载了 `Weixin.dll`）。

---

## 两个端口

| 端口 | 用途 | 能不能改 |
|---|---|---|
| **29731** | `wxhook.dll` 投递到 `127.0.0.1:29731/hook/payment` | 不能（DLL 里写死） |
| **29732** | 本地面板 | 能（`agent.json` 的 `panelAddr`） |

刻意分开：29731 被别的东西占了（比如你同时装了服务端），面板仍然能打开告诉你原因。

---

## 常见问题

### 状态一直是「Weixin.dll 未加载」

**注入到子进程了。** 微信 4.x 有多个 `Weixin.exe`，只有加载了 `Weixin.dll` 的那个才有效。

1. 面板点「查看微信进程」
2. 找「加载 Weixin.dll = 是」的那个（通常内存最大，几百 MB，其余是十几 MB）
3. 点它那行的「注入这个」

面板会直接红字提示「注入的进程不对」并给出正确 PID。

### 注入了但抓不到收款

**微信里可能挂着旧版 DLL。**

微信启动后 DLL 就加载住了，换文件不影响已加载的那份。
必须**完全退出微信**（托盘图标也退出）重新打开，再注入。

### 状态是 3 或 9（特征码不匹配）

微信版本变了。特征码是从 **4.1.12.53** 提取并验证的。

```powershell
# 需要 Python 3 + 对应版本的 Weixin.dll
python scripts\find_printpb.py "C:\Program Files\Tencent\Weixin\4.1.xx.xx\Weixin.dll"
python scripts\extract_signatures.py "..."   # 输出唯一特征码
python scripts\verify_hook_target.py "..."   # 验证精确命中

# 把输出加进 hook/src/Hook.cpp 的 kPrintPbPatterns，重编
```

### 上报报「密钥不一致」

Windows 的 `-token` 与服务器 `config.json` 的 `reportToken` 不同。改成一致，重启。

### 上报报「本机时间与服务器差超过 300 秒」

```powershell
w32tm /config /manualpeerlist:"ntp.aliyun.com" /syncfromflags:manual /update
w32tm /resync
```

### 队列一直涨

面板看「最近错误」。网关不通时事件会一直积压（这是设计——不丢单）。
恢复连接后自动补发。

---

## 技术要点

### 为什么用汇编跳板

`printpb` 没有公开签名，各版本 ABI 会变。用猜测的 C 签名去接会破坏栈上第 5 个之后的参数，直接崩微信。

`DetourStub.S` 只做「快照寄存器 → 交给 C 侧 → 原样恢复 → 尾跳回原逻辑」，不改栈、不改返回地址。

### 特征码怎么来的

不是通用函数序言（那种在大模块里能撞上百处）。流程：

1. `.rdata` 里找 `weapp_path` 字符串（收款 appmsg 独有，全模块只出现 1 次）
2. `.text` 里找引用它的 `lea reg,[rip+disp]` 指令
3. 回溯到函数入口
4. 取入口字节**逐步加长**，直到在 113 MB 的 `.text` 里只命中 1 次

结果（4.1.12.53）：`weapp_path.A` 32 字节、`weapp_path.B` 28 字节，各命中 1 处。

**双重判据**：特征码 + RVA 校验（±1 MB）。命中但偏太远就拒绝装钩——宁可报「版本不支持」也不让微信崩。

### appmsg 是 XML 不是 protobuf

真实样本（277 笔真实收款解密所得）：

```xml
<title><![CDATA[[店员消息]收款到账134.99元]]></title>
<des><![CDATA[收款金额￥134.99
收款门店:leochang]]></des>
<weapp_path>...&out_order_no=10259366458017948817520115990500&mch_id=805242195</weapp_path>
```

**坑**：链接收款一条消息里有**两个** `weapp_path`，第二个是 `link-qr-code` 页面不带单号。
必须遍历全部取第一个带 `out_order_no` 的。

---

## 文档

| 文件 | 内容 |
|---|---|
| `docs/HOOK.md` | 注入原理、状态码、版本支持、补特征码流程 |
| `docs/PROTOCOL.md` | 端到端协议、去重设计、重试矩阵 |

---

## 免责

仅供个人在自己合法持有的设备上使用。注入微信客户端可能违反服务条款，
账号风险自负。
