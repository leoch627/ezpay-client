# 给网页端开发者

你拿到的是 `wxpay-client/`。这里没有 React/Vue，`web/index.html` 是一个 38 KB 的
原生 JS 单页，`go:embed` 打进网关二进制。你可以整个重写，但下面这些**别踩坑**。

---

## 一、先跑起来

```powershell
cd wxpay-client
go build -o build\wxpayclient.exe .\cmd\gateway
cd build
.\wxpayclient.exe
```

浏览器开 `http://127.0.0.1:29731/`。

**这是本地工具，不是服务端。** 它的职责只有：注入微信 → 收事件 → 上报上游。
不要给它加登录、用户体系、多租户——它跑在操作员自己机器上，只有一个"用户"。

---

## 二、五件必须知道的事

### 1. 端口会变

默认 `127.0.0.1:29731`，被占用时网关自动顺延到 29732、29733…
**实际地址在 `/api/snapshot` 的 `listenAddr` 字段里。**

```js
// 别硬编码端口探测，直接读 snapshot
const snap = await fetch('/api/snapshot').then(r => r.json());
console.log(snap.listenAddr);   // "127.0.0.1:29732"
```

页面左下角要显示这个值，用户需要知道去哪打开。

### 2. 密钥永远拿不到明文

`GET /api/settings` 返回的是打码值：

```json
{ "reportToken": "my-s****c123", "hasSecret": true }
```

保存时**只在用户真的改了才提交**，否则会把打码值写回去：

```js
const body = { upstreamUrl, merchantId, /* ... */ };
const secret = secretInput.value;
if (secret) body.merchantSecret = secret;   // 留空 = 不修改
await fetch('/api/settings', { method: 'POST', body: JSON.stringify(body) });
```

后端拿到明文后立刻用 **Windows DPAPI** 加密成 `protectedMerchantSecret`，
并把 `reportToken` 清空再落盘。所以：

- 不要试图在前端"记住"密钥
- 不要做"显示已保存密钥"的功能，做不到
- 换机器 / 换 Windows 用户后旧密文解不开，必须重新填

### 3. 轮询就够了，别上 WebSocket

现有面板 2 秒轮询 `/api/snapshot`，一次约 1~2 KB，够用。

如果非要推，注意事件产生是**突发**的（收款瞬间来几条，然后几小时没有），
WebSocket 心跳反而增加复杂度。真要做，先从 `/api/snapshot` 的 `recent` 增量拉。

页面隐藏时记得停轮询：

```js
document.addEventListener('visibilitychange', () => {
  document.hidden ? stopPoll() : startPoll();
});
```

### 4. 指标从 `totals` 取，不要从 `hook`

```json
{
  "hook":   { "paymentCount": 0, "postOk": 0 },      ← Hook DLL 运行时计数，网关重启归零
  "totals": { "received": 7, "reported": 3,          ← 数据库累计，重启不丢
              "failed": 4, "amountCents": 103095 },
  "queue":  { "pending": 0, "paused": 0, "done": 3, "failed": 4 }
}
```

顶部的三个数字用 `totals`。`hook.*` 只用于「诊断」区，反映当前这个微信进程活着的期间命中了多少次。

金额是**分**（`amountCents`），显示时除以 100。**全链路金额都用整数分**，
前端不要引入浮点运算去算总额。

### 5. 三个"空"要区分开

用户看到空白最容易误判，务必给出不同文案：

| 状态 | 判据 | 该显示什么 |
|---|---|---|
| 网关没起 | `fetch` 抛异常 | 「网关未运行」+ 地址 + 怎么启动 |
| 微信没注入 | `hook.attached === false` | 「未注入」+ 点注入按钮 |
| 还没收到款 | `totals.received === 0` | 「暂无记录」，别报警 |

现在的面板对第一种是红色徽章「未连接」，后两种是黄色「未注入 / 暂无活动」。

---

## 三、API 速查（响应均为真实抓取）

### `GET /api/snapshot`

```json
{
  "hook": {
    "attached": false, "state": "未注入", "stateCode": 0, "pid": 0,
    "moduleBase": 0, "version": "", "requiredVersion": "",
    "patternId": "", "detail": "wxinject.dll 不可用",
    "callbackCount": 0, "paymentCount": 0, "postOk": 0, "postFail": 0,
    "dedupDrop": 0, "lastHitAt": 0
  },
  "queue":  { "pending": 0, "paused": 0, "done": 0, "failed": 0 },
  "totals": { "received": 0, "reported": 0, "failed": 0, "amountCents": 0 },
  "recent": [],
  "uptime": 3,
  "version": "dev",
  "serverOk": false,
  "serverNote": "不可达：dial tcp 127.0.0.1:8080: connectex: ...",
  "listenAddr": "127.0.0.1:29731"
}
```

`recent` 每项：

```json
{ "at": 1794962982, "kind": "payment", "level": "info",
  "message": "收到收款 amount=134.99 source_key=wechat:8230181883717811380",
  "amount": "134.99", "nonce": "n-8f0ebd01ce1a38f60f3f4a1e" }
```

`kind` 取值：`payment` / `report` / `hook` / `channel` / `codes` / `settings` / `error`
`level` 取值：`info` / `warn` / `error`

### `GET /api/account`

```json
{
  "provider": "wechat", "accountId": "", "exePath": "C:\\Program Files\\Tencent\\Weixin\\Weixin.exe",
  "exeExists": true, "running": false, "pid": 0,
  "version": "4.1.12.53", "channelId": "", "codeCount": 0
}
```

`version` 读的是 `Weixin.exe` 的 PE 版本资源，可靠。
**别去读注册表的 Version DWORD 做位运算**——那是微信自定义编码，
`0xF254200D` 按常规位运算会解成 `242.84.32.13`，真实是 `4.1.48.13`。

`accountId` 来自最近一条收款事件，没收到过款就是空串。

### `GET /api/settings`

```json
{
  "upstreamUrl": "http://127.0.0.1:8080", "merchantId": "",
  "reportToken": "", "hasSecret": false,
  "channel": "wechat", "listenAddr": "127.0.0.1:29731",
  "httpTimeoutSec": 45, "source": "inject",
  "autoInject": true, "disableWeChatUpdate": true, "accountId": ""
}
```

### `POST /api/settings`

只传要改的字段（其余保持原值）：

```json
{ "upstreamUrl": "...", "merchantId": "10059", "merchantSecret": "明文新密钥",
  "listenAddr": "127.0.0.1:29731", "httpTimeoutSec": 45, "source": "inject" }
```

校验失败返回 **400**：

```json
{ "error": "配置有问题", "problems": ["商户 ID 不能为空", "上报超时不能小于 45 秒"] }
```

`problems` 是数组，逐条展示。

### `POST /api/channels` / `GET /api/channels`

```json
// GET
{ "items": { "wechat:wxid_jalj9ys3nz8u12": "6552" } }

// POST
{ "provider": "wechat", "accountId": "wxid_xxx", "channelId": "6552" }
```

`channelId` 传空串 = **解绑**，上报时走上游默认通道。
只允许字母数字 `-` `_`，最长 64。

### `GET /api/codes?provider=wechat&accountId=wxid_xxx`

```json
{ "items": [ { "key": "item_a", "name": "测试2", "priceCents": 10 } ] }
```

### `POST /api/codes`

整体替换：

```json
{ "provider": "wechat", "accountId": "wxid_xxx",
  "items": [ { "key": "item_a", "name": "测试2", "priceCents": 10 } ] }
```

`key` 必须非空且唯一（前端生成，如 `item_${Date.now()}`）。
金额超过 10 万元会被拒。

### `GET /api/queue?limit=100`

```json
{ "count": 0, "items": [] }
```

每项关键字段：`amount` `state` `lastMsg` `attempts` `nonce` `tradeNo`
`state` ∈ `pending` / `paused` / `done` / `failed`

### `GET /api/selftest`

```json
{ "ok": true, "pingOk": true, "pingNote": "OK (status=none)", "tokenOk": true,
  "tokenNote": "密钥正确（服务端返回 bad amount，符合预期）", ... }
```

注意字段名和 `/api/snapshot` 不一样：自检这里是 `pingOk` / `pingNote`，
snapshot 里缓存的启动自检才叫 `serverOk` / `serverNote`。

```
```

**响应可能很慢**：上游匹配成功时会同步等它回调商户，最长约 33 秒。
前端请求超时给到 **60 秒**，并显示 loading。

### 其它

| 路由 | 说明 |
|---|---|
| `POST /api/queue/requeue` | 把 paused 全部转 pending 并立刻重试，返回 `{requeued, resumed}` |
| `POST /api/inject` | body `{"exe":"Weixin.exe"}` 或 `{"pid":1156}`，需管理员权限 |
| `POST /api/mock/payment` | 造一笔假收款，联调用 |
| `GET /api/queue/{id}/candidates` | 补单候选：收款站上实付金额相同的订单 `{amount, orders[]}` |
| `POST /api/queue/{id}/complete` | 人工补单 `{"tradeNo":"..."}`，仅 `failed` 记录；成功后记录转 `done`。返回 `{notifyOk, notifyMsg, already}`，**超时给 70 秒** |
| `POST /api/queue/{id}/renotify` | 重发商户回调，仅已匹配（`done` 且有 `tradeNo`）的记录 |
| `POST /api/test-order` | 在收款站建测试单 `{"amount":"0.01"}`，返回 `{order, payUrl}`；实付以 `order.realMoney` 为准 |
| `GET /api/test-order/{tradeNo}` | 查测试单状态（面板 2 秒轮询） |

补单 / 测试单走收款站后台接口（HTTP Basic），要先在设置里填 `adminUser` / `adminPass`
（`POST /api/settings`，密码同商户密钥一样加密落盘、永不回显，GET 只给 `hasAdminPass`）。
没配时这几个接口回 **412**；收款站不是 wxpay-epay、没有这组接口时回 502 并提示"不支持后台补单"。
| `GET /api/health` | 存活探针 |
| `GET/POST /api/epay/{path}` | 原样转发到收款站本机后台 `/admin/api/{path}`（订单 `orders/list` `order` `order/close`、商户 `merchants` `merchant` `merchant/reset-key`、站点 `settings`、收款码 `qrcode`（POST 原始图片字节）、统计 `overview`、`sign-debug`、`export`）。错误字段是 `err`；上游 401 被改写成 502，不会把面板踢回登录页 |
| `POST /api/report-token/rotate` | 生成新上报密钥，同时写进收款站和网关，立即生效 |
| `POST /api/alert/test` | `{"webhook":"..."}` 发一条测试告警；告警地址和开关在 `/api/settings` 的 `alertWebhook` `alertOffline` `alertUnmatched` `alertNotifyFail` |
| `GET /qrcode/{file}` | 收款码图片（线上由 nginx 直接给收款站，这里是没有 nginx 时的兜底） |
| `POST /hook/payment` | **wxhook.dll 专用**，前端不要调 |

---

## 四、样式与体验约定

现有面板的取向，建议保留：

- **浅色为主，跟随系统深色**（`@media (prefers-color-scheme: dark)` 改 CSS 变量）
- **不引任何 CDN**。这个程序经常跑在没外网的机器上，`<script src="https://...">` 直接白屏
- **中文界面**。所有文案、错误提示、按钮都用中文
- 卡片圆角 10px，1px 描边，不要重投影
- 数字用 `font-variant-numeric: tabular-nums`，否则金额会跳
- 状态用徽章色：成功绿 / 警告黄 / 失败红，不要只靠文字

金额显示：

```js
const yuan = (cents / 100).toFixed(2);   // 103095 -> "1030.95"
```

**元转分不要用 `parseFloat(x) * 100`**——`19.99 * 100 = 1998.9999999999998`，
`Math.round` 偶尔也会错一分钱。用字符串解析，与后端 `codes.YuanToCents` 一致：

```js
function yuanToCents(s) {
  let whole = 0, frac = 0, digits = 0, dot = false, any = false;
  for (const ch of s) {
    if (ch >= '0' && ch <= '9') {
      any = true;
      if (dot) { if (digits >= 2) continue; frac = frac * 10 + +ch; digits++; }
      else whole = whole * 10 + +ch;
    } else if (ch === '.') { if (dot) return null; dot = true; }
    else if (' ¥￥\t'.includes(ch)) { /* 忽略 */ }
    else return null;
  }
  if (!any) return null;
  while (digits++ < 2) frac *= 10;
  return whole * 100 + frac;
}
```

---

## 五、不要做的事

| 别做 | 原因 |
|---|---|
| 把 `reportToken` 存 localStorage / 回显 | 后端从不下发明文，存了也是打码值 |
| 直接读 `data/config.json` 当配置源 | 里面 `reportToken` 是空的，密钥在 `protectedMerchantSecret`（DPAPI 密文） |
| 前端直接调上游 `/api/report` | 签名必须由后端算，前端算等于把密钥交出去 |
| 给 `/hook/payment` 加 CORS | 它只给本机 wxhook 用 |
| 假设 29731 一定可用 | 读 `listenAddr` |
| 用 `parseFloat` 算金额 | 见上 |
| 引 UI 框架 | 38 KB 单页够快，加框架反而要处理构建链 |
| 改 `/api/settings` 的字段名 | 后端 struct tag 写死了 camelCase，改了就 400 |

---

## 六、可以放心依赖的行为

- 所有 `GET` 都是幂等的
- `POST /api/settings` 成功后**立刻生效**，不用重启
- 队列先落盘再发送，进程崩溃不丢单
- 同一笔收款重复投递会被去重（按 `msgId`），返回 `{dup:true}`，不会重复上报
- 密钥错了会自动 `paused` 并停止上报，修好后点「恢复暂停项」即可，不丢队列
- 事件表只留最近 2000 条，自动清理

---

## 七、想改后端时

C++ 那部分（`hook/`）**最好别动**。特征码是从真实 `Weixin.dll 4.1.12.53` 提取并验证唯一的，
改错会导致钩错函数、微信崩溃。要支持新版本，照 `docs/HOOK.md` 的流程提特征码。

Go 侧随便改，改完跑：

```powershell
go build ./... ; go vet ./... ; go test ./internal/...
powershell -File scripts\test.ps1      # 解析器回归，84 项
```

`scripts/test.ps1` 用的是 12 条**真实收款记录**（DPAPI 解密自真实数据库），
改 appmsg 解析逻辑后必须跑。

---

## 八、目前最想被改进的地方

老实说：

1. **`web/index.html` 是一个文件写的，已经 1100 行**。要扩展建议先拆成 `api.js` / `pages/*.js`，
   用原生 ES module，仍然不需要构建链。
2. **没有金额趋势图**。`totals` 只有累计值，要画图得后端加按天聚合的接口。
   如果要做，记得金额一律整数分。
3. **日志页只能看不能搜**。加个前端过滤输入框很容易，`recent` 就 50 条。
4. ~~队列没有单条重试~~ 已有 `POST /api/queue/{id}/retry`，失败记录另有人工补单。
5. **移动端布局只是勉强能用**（侧栏折叠成图标）。这个程序主要在 PC 上用，优先级低。
