package model

// 上报结果分类（文档 §4.4）
type Outcome string

const (
	OutcomeDone  Outcome = "done"  // 出队
	OutcomeAlert Outcome = "alert" // 出队 + 告警
	OutcomePause Outcome = "pause" // 暂停上报（密钥错）
	OutcomeRetry Outcome = "retry" // 留队，退避重试
)

// ReportItem 是队列里的持久化单元。
// 关键：body 在入队时**一次性序列化成字符串**，之后每次重试都重发同一段字节。
// 文档 §4.2 明确要求「先序列化成字符串，再签名，再原样发送」。
type ReportItem struct {
	ID          int64  `json:"id"`
	Amount      string `json:"amount"` // 两位小数字符串，如 "10.01"
	TS          int64  `json:"ts"`     // 入队时的时间戳，重试不变
	Nonce       string `json:"nonce"`  // 每笔到账唯一，重试复用
	Channel     string `json:"channel"`
	Raw         string `json:"raw"`
	SourceKey   string `json:"sourceKey"`   // 真实主去重键：provider + ":" + msgId（REAL_DATA §2）
	MsgID       string `json:"msgId"`       // 微信 19 位 msgId，拿不到为空
	Fingerprint string `json:"fingerprint"` // 二级去重：sha256(raw+receivedAt 秒) 前 16 位

	// 商户/门店上下文，仅记录（REAL_DATA §7#6）。不参与上报 body，只给面板排查用。
	MchID      string `json:"mchId,omitempty"`
	ShopID     string `json:"shopId,omitempty"`
	SourceType string `json:"sourceType,omitempty"` // SHOP_QRCODE | MCH_QRCODE
	ReceivedAt int64  `json:"receivedAt"`           // 消息时间（秒），去重指纹的素材
	AccountID  string `json:"accountId,omitempty"`  // 收款账号 wxid_xxx，用于通道绑定

	Body      string `json:"body"` // 已序列化的 JSON body，签名对象
	Attempts  int    `json:"attempts"`
	NextTry   int64  `json:"nextTry"` // unix 秒
	State     string `json:"state"`   // pending | paused | done | failed
	LastMsg   string `json:"lastMsg"`
	LastCode  int    `json:"lastCode"`
	TradeNo   string `json:"tradeNo"` // matched 时服务端返回
	CreatedAt int64  `json:"createdAt"`
}

// ReportResponse 服务端 /api/report 响应体。
//
// 真实协议（REAL_DATA §3.1/3.2）与开发文档 §4.4 是两套，必须同时兼容：
//
//	真实成功 {"code":200,"message":"上报订单匹配成功","data":{"order_id":"..."},"redirect":""}
//	真实失败 {"code":502,"message":"没有找到匹配...","data":{},"redirect":""}
//	文档成功 {"code":1,"msg":"matched","trade_no":"..."}
//	文档重复 {"code":0,"msg":"duplicate ignored"}
type ReportResponse struct {
	// 真实协议字段
	Code     int             `json:"code"`
	Message  string          `json:"message"`
	Data     ReportRespData  `json:"data"`
	Redirect string          `json:"redirect"`

	// 开发文档字段（兼容保留）
	Msg     string `json:"msg"`
	TradeNo string `json:"trade_no"`

	// 未在原始 body 里出现，由解析器归一化后填写，便于上层与日志统一使用
	NormalizedMsg  string `json:"-"`
	NormalizedCode int    `json:"-"`
	NormalizedRef  string `json:"-"` // 实际用于出队的单号
}

// ReportRespData 真实协议里 data 是一个对象，成功时带 order_id。
// 用 struct 而不是 map，避免服务端偶尔回 data:null 时解析报错。
type ReportRespData struct {
	OrderID string `json:"order_id"`
}

// OrderStatus /api/order_status 响应
type OrderStatus struct {
	Status    string `json:"status"` // pending|paid|notified|expired|none
	ReturnURL string `json:"return_url"`
}

// Snapshot 给本地面板：注入器状态 + 队列统计 + 最近事件
type Snapshot struct {
	Hook       HookStatus    `json:"hook"`
	Queue      QueueStats    `json:"queue"`
	Totals     Totals        `json:"totals"`
	Recent     []RecentEvent `json:"recent"`
	Uptime     int64         `json:"uptime"`
	Version    string        `json:"version"`
	ServerOK   bool          `json:"serverOk"`
	ServerNote string        `json:"serverNote"`

	// ListenAddr 是**实际**监听地址。config 里的 listenAddr 可能因端口被占用而
	// 被自动 fallback 到下一个可用端口，面板必须显示真实值，否则用户按配置里的
	// 地址访问会 404 / 连不上。
	ListenAddr string `json:"listenAddr"`

	// Agents 是所有连过来的 Windows 代理；Hook 字段取自其中最近在线的那台。
	Agents []AgentStatus `json:"agents"`
}

// HookStatus 对应 hook/include/wxhook_abi.h 的 wxhook_status
type HookStatus struct {
	Attached    bool   `json:"attached"`
	State       string `json:"state"`
	StateCode   uint32 `json:"stateCode"`
	PID         uint32 `json:"pid"`
	ModuleBase  uint64 `json:"moduleBase"`
	Version     string `json:"version"`
	Required    string `json:"requiredVersion"`
	PatternID   string `json:"patternId"`
	Detail      string `json:"detail"`
	CallbackCnt uint64 `json:"callbackCount"`
	PaymentCnt  uint64 `json:"paymentCount"`
	PostOK      uint64 `json:"postOk"`
	PostFail    uint64 `json:"postFail"`
	DedupDrop   uint64 `json:"dedupDrop"`
	LastHitAt   int64  `json:"lastHitAt"`
}

type QueueStats struct {
	Pending int `json:"pending"`
	Paused  int `json:"paused"`
	Done    int `json:"done"`
	Failed  int `json:"failed"`
}

// Totals 是业务累计计数，全部来自数据库（重启不丢）。
// 面板顶部的三个数字用这个，不要用 HookStatus 里的运行时计数器。
type Totals struct {
	Received    int   `json:"received"`    // 累计入库的收款事件数
	Reported    int   `json:"reported"`    // 累计上报成功数（done）
	Failed      int   `json:"failed"`      // 累计失败数（failed）
	AmountCents int64 `json:"amountCents"` // 累计金额（分）
}

type RecentEvent struct {
	At      int64  `json:"at"`
	Kind    string `json:"kind"`  // payment | report | error | hook
	Level   string `json:"level"` // info | warn | error
	Message string `json:"message"`
	Amount  string `json:"amount,omitempty"`
	Nonce   string `json:"nonce,omitempty"`
}

// HookEvent 是 wxhook.dll → POST /hook/payment 的真实字段集（REAL_DATA §1/§8）。
// 字段名与 hook/src/Sender.cpp 的 BuildJson 逐一对齐。
type HookEvent struct {
	Provider   string `json:"provider"`    // wechat
	Amount     string `json:"amount"`      // 两位小数字符串
	TransNo    string `json:"transNo"`     // = out_order_no
	Sender     string `json:"sender"`      // gh_f0a92aa7146c 之类
	AccountID  string `json:"accountId"`   // wxid_xxx
	ReceivedAt int64  `json:"receivedAt"`  // unix 秒
	Raw        string `json:"raw"`         // appmsg XML 原文
	MsgID      string `json:"msgId"`       // 19 位数字，主去重键
	MchID      string `json:"mchId"`       // 微信支付商户号
	ShopID     string `json:"shopId"`      // 收款商业版门店 ID
	SourceType string `json:"sourceType"`  // SHOP_QRCODE | MCH_QRCODE
}

// ServerStatus 启动自检结果的缓存，给 snapshot 用。
type ServerStatus struct {
	PingOK     bool   `json:"pingOk"`
	PingNote   string `json:"pingNote"`
	TokenOK    bool   `json:"tokenOk"`
	TokenNote  string `json:"tokenNote"`
	CheckedAt  int64  `json:"checkedAt"`
}

// DayTotal 是按天聚合的收款，给面板画趋势。
type DayTotal struct {
	Day         string `json:"day"` // 2006-01-02，网关本地时区
	Count       int    `json:"count"`
	AmountCents int64  `json:"amountCents"`
}

// WeChatInfo 是 Windows 代理探测到的本机微信情况。
type WeChatInfo struct {
	ExePath   string `json:"exePath"`
	ExeExists bool   `json:"exeExists"`
	Running   bool   `json:"running"`
	PID       uint32 `json:"pid"`
	Version   string `json:"version"` // 读 PE 版本资源，不是注册表 DWORD
}

// AgentStatus 是 Windows 代理每次心跳上报的本机状态。
// 网关不再自己注入微信，Hook 状态、微信版本都以代理上报为准。
type AgentStatus struct {
	AgentID      string     `json:"agentId"`
	Hostname     string     `json:"hostname"`
	Version      string     `json:"version"`
	Hook         HookStatus `json:"hook"`
	WeChat       WeChatInfo `json:"wechat"`
	InjectorOK   bool       `json:"injectorOk"`
	InjectorNote string     `json:"injectorNote"`
	Outbox       int        `json:"outbox"`    // 代理本地还没送达网关的事件数
	LastError    string     `json:"lastError"` // 代理最近一次转发/注入错误

	// Results 是上一轮心跳取走的指令的执行结果，网关写进事件流后丢弃
	Results []CommandResult `json:"results,omitempty"`

	// 以下由网关填写
	SeenAt     int64  `json:"seenAt"`
	RemoteAddr string `json:"remoteAddr"`
	Online     bool   `json:"online"`
}

// AgentCommand 是网关下发给代理的指令（代理在心跳响应里取走）。
type AgentCommand struct {
	ID   string `json:"id"`
	Type string `json:"type"` // inject
	Exe  string `json:"exe,omitempty"`
	PID  uint32 `json:"pid,omitempty"`
}

// AgentPolicy 是网关集中下发给代理的开关，面板上改一次，所有代理跟着变。
type AgentPolicy struct {
	AutoInject          bool `json:"autoInject"`
	DisableWeChatUpdate bool `json:"disableWeChatUpdate"`
	InjectIntervalSec   int  `json:"injectIntervalSec"`
}

// HeartbeatResponse 是 POST /api/agent/heartbeat 的响应。
type HeartbeatResponse struct {
	OK         bool           `json:"ok"`
	ServerTime int64          `json:"serverTime"`
	Policy     AgentPolicy    `json:"policy"`
	Commands   []AgentCommand `json:"commands"`
}

// AgentEvent 是代理转发给网关的一笔收款：原样带上 wxhook 的 HookEvent。
type AgentEvent struct {
	AgentID string    `json:"agentId"`
	Seq     int64     `json:"seq"` // 代理本地 outbox 的 id，只用于日志对账
	Event   HookEvent `json:"event"`
}

// CommandResult 是代理执行指令后的回执。
type CommandResult struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}
