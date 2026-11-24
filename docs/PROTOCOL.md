# 端到端协议

三段协议：微信 → Hook → 网关 → 商户平台。

---

## 1. wxhook.dll → 网关

`POST http://127.0.0.1:29731/hook/payment`
`Content-Type: application/json`

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `provider` | string | ✓ | 固定 `wechat` |
| `amount` | string | ✓ | **两位小数字符串**，如 `"134.99"`（不是 `"134.9"` 或数字） |
| `transNo` | string | | 微信侧订单号 = `out_order_no` |
| `sender` | string | | 收款公众号 wxid，如 `gh_f0a92aa7146c` |
| `accountId` | string | | 收款账号 wxid |
| `receivedAt` | number | ✓ | unix 秒 |
| `raw` | string | ✓ | 微信 appmsg XML 原文（完整，便于事后核对） |
| `msgId` | string | ★ | 微信 msgId，**主去重键**，19 位数字 |
| `mchId` | string | | 微信支付商户号 |
| `shopId` | string | | 微信收款商业版门店 ID |
| `sourceType` | string | | `SHOP_QRCODE` / `MCH_QRCODE` |

示例：
```json
{
  "provider": "wechat",
  "amount": "134.99",
  "transNo": "10259366458017948817520115990500",
  "sender": "gh_f0a92aa7146c",
  "accountId": "wxid_jalj9ys3nz8u12",
  "receivedAt": 1794881757,
  "raw": "<?xml version=\"1.0\"?><msg><appmsg>...</appmsg></msg>",
  "msgId": "8230181883717811380",
  "mchId": "805242195",
  "shopId": "43030953",
  "sourceType": "SHOP_QRCODE"
}
```

响应：
```json
{"ok": true, "dup": false, "id": 1, "nonce": "n-8f0ebd01ce1a38f60f3f4a1e", "amount": "134.99"}
{"ok": true, "dup": true,  "nonce": "n-8f0ebd01ce1a38f60f3f4a1e", "amount": "134.99"}
```

---

## 2. 微信 appmsg XML 里要抽什么

**真实样本**（从 277 笔真实收款记录解密得到）：

```xml
<?xml version="1.0"?>
<msg>
  <appmsg appid="" sdkver="0">
    <title><![CDATA[[店员消息]收款到账134.99元]]></title>
    <des><![CDATA[收款金额￥134.99
收款门店:leochang
收款说明:经营收款事项
说明:已存入店长leochang(**店)的经营账户]]></des>
    <type>5</type>
    <mmreader>
      <category><topnew><item>
        <pub_time>1794881757</pub_time>
        <weapp_path><![CDATA[pages/mini-receipt/order-detail/order-detail.html
          ?account_type=E_MINI_RECEIPT_EACCOUNT_TYPE_SJT
          &source_type=E_ORDER_TRADE_FROM_TYPE_SHOP_QRCODE
          &shop_id=43030953
          &out_order_no=10259366458017948817520115990500
          &mch_id=805242195
          &from=mini_receipt_assistant_msg_detail]]></weapp_path>
      </item></topnew></category>
    </mmreader>
  </appmsg>
</msg>
```

### 抽取规则

| 目标 | 来源 | 规则 |
|---|---|---|
| 金额 | `<title>` 优先，其次 `<des>` | `收款到账(\d+\.\d{2})元` 或 `收款金额￥(\d+\.\d{2})` |
| 订单号 | `<weapp_path>` 的 query | `out_order_no=([A-Za-z0-9-]{16,40})` |
| 商户号 | 同上 | `mch_id=(\d+)` |
| 门店 ID | 同上 | `shop_id=(\d+)` |
| 来源类型 | 同上 | `source_type=E_ORDER_TRADE_FROM_TYPE_(\w+)` → 取尾部 |
| 时间 | `<pub_time>` | 最后一个（mmreader 里的才是正文） |
| 门店名 | `<des>` | `收款门店[:：]([^\r\n]+)` |

### 两个必须注意的坑

**坑 1：链接收款有两个 `weapp_path`**

一条 `MCH_QRCODE` 消息里有：
```
① pages/mini-receipt/order-detail/...   ← 有 out_order_no
② pages/link-qr-code/index/index.html   ← 只有 receipt_id，没有单号
```
取"最后一个"会漏单号。**必须遍历全部，取第一个带 `out_order_no` 的。**

**坑 2：同一笔收款产生两条 appmsg**

```
[店员消息]收款到账134.99元      ← 店员视角
经营码收款到账通知              ← 官号视角
```
两条 `out_order_no` 相同、`mch_id` 相同，但 `msgId` 不同。
→ 所以必须有 `out_order_no` 级去重（见 §4）。

### 过滤规则

以下一律丢弃：
- 含 `退款` / `已退款` / `撤销`
- `<title>` 含 `转账`（那是"你付给别人"）
- 没有 `out_order_no`（无法去重，宁可丢）
- 金额不在 `0.01 ~ 100000` 元

---

## 3. 网关 → 商户平台

`POST {serverUrl}/api/report`
`Content-Type: application/json`
`X-Sign: <lower_hex>`

### body（紧凑 JSON，无空格）

```json
{"amount":"134.99","ts":1794962982,"nonce":"n-8f0ebd01ce1a38f60f3f4a1e","channel":"wechat","raw":"..."}
```

| 字段 | 说明 |
|---|---|
| `amount` | 两位小数字符串 |
| `ts` | **入队时**的时间戳，重试不变 |
| `nonce` | 每笔唯一，重试复用 |
| `channel` | 默认 `wechat` |
| `raw` | appmsg XML 原文 |

### 签名

```
X-Sign = lower_hex( HMAC-SHA256( key = reportToken, message = body 的原始字节 ) )
```

**关键**：先序列化成字符串 → 对这段字节签名 → 原样发送。
不要让 HTTP 库二次序列化（字段顺序一改签名就废）。

### 服务端响应（真实格式）

**成功**
```json
{"code":200,"message":"上报订单匹配成功","data":{"order_id":"20261117101531952456"},"redirect":""}
```

**失败（订单超时 / 通道不匹配）**
```json
{"code":502,"message":"没有找到匹配对应支付方式和通道信息对应支付金额的订单,可能已过期或通道不匹配导致","data":{},"redirect":""}
```

### 客户端判定（兼容两套协议）

| 条件 | 结果 | 处理 |
|---|---|---|
| `code==200` 且 `message` 含 "匹配成功" | done | 出队，记 `data.order_id` |
| `code==1` 且 `msg=="matched"` | done | 出队，记 `trade_no`（文档版协议） |
| `msg`/`message` 含 "duplicate" | done | 出队（重试时前次其实成功了） |
| HTTP 401 | **pause** | 暂停整个队列并告警（token 不一致） |
| HTTP 5xx / 网络错误 / 超时 | retry | 留队退避 |
| 其他 `code`（如 502） | alert | 出队 + 告警"需人工补单" |

> 为什么兼容两套：`收款客户端开发文档` 说 `{code:1,msg:"matched"}`，
> 但真实抓包（277 笔）是 `{code:200,message:"上报订单匹配成功"}`。
> 真实数据优先，同时保留文档版以兼容其他实现。

### 超时要求

**必须 ≥ 45 秒。**

原因：匹配成功时服务端会同步等待商户回调结束才返回响应：
- 商户拒绝连接 → 约 9 秒
- 商户超时 → 最长约 33 秒

客户端 `httpTimeoutSec` 低于 45 会大量误判超时。代码里强制下限 45。

---

## 4. 三级去重

这是整个系统最要紧的部分。**重复上报 = 商户重复记账 = 资金差错。**

```
第一级：进程内环形缓冲（wxhook.dll）
  64 条 source_key 环，命中即丢弃，不投递
  → 挡住 printpb 在同一次消息处理中被调多次

第二级：SQLite seen 表（网关）
  主键：source_key = "wechat:" + msgId
  命中 → 复用已有 nonce，不入队，回 dup:true
  → 挡住微信重连/重扫导致的消息重放

第三级：服务端 nonce 去重
  同 nonce 再上报 → {"code":0,"msg":"duplicate ignored"} 或 200
  → 挡住网络层重传
```

### msgId 缺失时的降级

```go
if msgId != "" {
    sourceKey = "wechat:" + msgId          // 一级键
} else {
    fingerprint = sha256(raw + receivedAt秒)[:16]  // 二级键
}
```

### 为什么 source_key 是 `wechat:数字` 而不是哈希

真实数据 277 笔的 `source_key` 全是 `wechat:<19位数字>` —— 那是微信 msgId。
原程序就是这么做的，直接沿用。

---

## 5. 重试矩阵

| 触发 | 动作 | 退避 |
|---|---|---|
| 网络错误 / 超时 | retry | 2s → 5s → 10s → 30s → 60s（封顶） |
| HTTP 5xx | retry | 同上 |
| HTTP 401 | **pause** 整个队列 | 人工修 token 后 `/api/queue/requeue` |
| `code:502`（未匹配） | 出队 + 告警 | — |
| `ts skew` | 出队 + 告警 | — |
| `bad amount` | 出队 + 告警（解析 bug） | — |
| `matched` / `duplicate` | 出队 | — |

`maxRetry=0` 表示无限重试（默认）；`>0` 时超过次数转 `failed`。

### ts 与重试的关系

`ts` 写在 body 里并参与签名，**重试时复用原 body**（同 ts、同 nonce）。

但服务端校验 `|now - ts| <= 300 秒`。所以：
- 积压 < 5 分钟的能补发成功
- 积压 > 5 分钟会被拒为 `ts skew` → **不要改 ts 硬发**，转人工补单

→ 客户端本机必须开 NTP 自动同步。

---

## 6. 时间同步

| 要求 | 值 |
|---|---|
| 服务端允许偏差 | 300 秒 |
| 建议本机 NTP | `w32tm /config /manualpeerlist:"ntp.aliyun.com" /syncfromflags:manual /update` |
| 检查 | `w32tm /query /status` |

---

## 7. 完整时序（一次收款）

```
t=0     用户扫码付款
t=+1s   微信客户端收到 appmsg
        └→ printpb 被调用 → WxhDetourStub → WxhCapture
           解析出 134.99 / 1025936... / 805242195 / SHOP_QRCODE
t=+1s   SenderPush → 工作线程 WinHttp POST（3s 超时）
t=+1s   网关 /hook/payment
        ├ source_key = wechat:8230181883717811380
        ├ seen 表未命中 → 生成 nonce → 序列化 body → 入队（先进磁盘）
        └ 返回 {"ok":true,"dup":false}
t=+2s   monitor 工作器取到该条 → 签名 → POST /api/report
t=+2s   商户平台匹配订单 → code 200 order_id=...
t=+2s   网关标记 done，记 order_id，写事件日志
t=+2s   面板 2 秒轮询看到记录
```
