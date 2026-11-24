# scripts/mock_hook.ps1 —— 模拟 wxhook.dll 往本机 wxhook.exe 推一条「收款到账」事件
#
# 用途：没有真微信、没有 DLL 的情况下，直接把一条到账事件 POST 到 wxhook.exe 的
#       /hook/payment，用它来跑通「事件 → 队列 → 上报服务端」整条链路。
#
# 字段与 hook/src/Sender.cpp 里拼的 OutEvent JSON 一致（顺序也一致）：
#   provider / amount / transNo / sender / accountId / receivedAt / raw
#   + real-data 补全的 msgId / mchId / shopId / sourceType
#     （见 reimpl/source/REAL_DATA.md §一，真实数据里靠 msgId 做 source_key 去重）
#
# 用法：
#   .\mock_hook.ps1                                        # 推到 127.0.0.1:29731（wxhook 的 hook 端口）
#   .\mock_hook.ps1 -Amount 10.00 -Raw "微信支付收款10.00元到账"
#   .\mock_hook.ps1 -Kind mchqr -Amount 25.50              # 链接收款形态的 transNo
#   .\mock_hook.ps1 -Server http://127.0.0.1:19090
#   .\mock_hook.ps1 -MsgId 4609609689842888458             # 指定 msgId，用来复现「同一条消息推两次」
#
# 退出码：0 = wxhook 返回 2xx；1 = 请求失败或返回非 2xx

[CmdletBinding()]
param(
    # 到账金额。字符串，两位小数；网关会自己再规范化一次
    [string]$Amount = "10.01",

    # 通知原文。默认取最常见的个人码文案；真实经营码文案见 README
    [string]$Raw = "微信支付收款10.01元到账",

    # 网关地址（wxhook.dll 默认推到这里）
    [string]$Server = "http://127.0.0.1:29731",

    # 微信侧订单号。留空则按 -Kind 自动生成
    [string]$TransNo = "",

    # 付款人昵称
    [string]$Sender = "测试用户",

    # 收款形态：shopqr = 经营码（32 位纯数字订单号），mchqr = 链接收款（分段带横杠）
    [ValidateSet("shopqr", "mchqr")]
    [string]$Kind = "shopqr",

    # 微信服务端消息 ID，19 位数字。留空自动生成；网关靠它做 source_key 去重
    [string]$MsgId = "",

    # 商户号 / 门店号，取值来自真实样本，只在排查时才有意义
    [string]$MchId = "805242195",
    [string]$ShopId = "43030953",

    # 账户标识，wxhook 里是登录态 wxid
    [string]$AccountId = "wxid_test",

    # 事件时间（unix 秒）。留空取当前时间；复现「同一条消息被捕获两次」时要传同一个值
    [long]$ReceivedAt = 0,

    # 覆盖 sourceType。留空则按 -Kind 推导
    [string]$SourceType = "",

    # 请求超时（秒）
    [int]$TimeoutSec = 15
)

$ErrorActionPreference = "Stop"

# ── 小工具 ────────────────────────────────────────────────────────────

# 生成 n 位随机纯数字字符串，首位非 0（避免出现前导 0 的 ID）
function New-Digits([int]$n) {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append((Get-Random -Minimum 1 -Maximum 10).ToString())
    for ($i = 1; $i -lt $n; $i++) {
        [void]$sb.Append((Get-Random -Minimum 0 -Maximum 10).ToString())
    }
    return $sb.ToString()
}

# 生成 n 位大写字母数字串
function New-Alnum([int]$n) {
    $chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $n; $i++) {
        [void]$sb.Append($chars[(Get-Random -Minimum 0 -Maximum $chars.Length)])
    }
    return $sb.ToString()
}

# 真实形态的 out_order_no：
#   经营码     10259366458017948817520115990500     → 32 位纯数字
#   链接收款   TON3UZ-00BT0SR-0DBF4UR-KP94HZ8I      → 6-7-7-8 分段，横杠连接
function New-TransNo([string]$kind) {
    if ($kind -eq "shopqr") {
        return (New-Digits 32)
    }
    return (New-Alnum 6) + "-" + (New-Alnum 7) + "-" + (New-Alnum 7) + "-" + (New-Alnum 8)
}

# 手写 JSON 转义：ConvertTo-Json 在 Windows PowerShell 5.1 会把中文转成 \uXXXX，
# 这里保持原文可读，方便对着网关日志肉眼核对。
function ConvertTo-JsonString([string]$s) {
    if ($null -eq $s) { return '""' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($ch in $s.ToCharArray()) {
        switch ($ch) {
            '"'  { [void]$sb.Append('\"'); continue }
            '\'  { [void]$sb.Append('\\'); continue }
            "`b" { [void]$sb.Append('\b'); continue }
            "`f" { [void]$sb.Append('\f'); continue }
            "`n" { [void]$sb.Append('\n'); continue }
            "`r" { [void]$sb.Append('\r'); continue }
            "`t" { [void]$sb.Append('\t'); continue }
            default {
                if ([int]$ch -lt 0x20) {
                    [void]$sb.Append(('\u{0:x4}' -f [int]$ch))
                } else {
                    [void]$sb.Append($ch)
                }
            }
        }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

# ── 组装事件 ──────────────────────────────────────────────────────────

if ([string]::IsNullOrWhiteSpace($TransNo)) { $TransNo = New-TransNo $Kind }
if ([string]::IsNullOrWhiteSpace($MsgId))   { $MsgId   = New-Digits 19 }
if ($ReceivedAt -le 0) { $ReceivedAt = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
if ([string]::IsNullOrWhiteSpace($SourceType)) {
    $SourceType = if ($Kind -eq "shopqr") { "E_ORDER_TRADE_FROM_TYPE_SHOP_QRCODE" } else { "E_ORDER_TRADE_FROM_TYPE_MCH_QRCODE" }
}

# 字段顺序与 hook/src/Sender.cpp 拼出来的 JSON 一致，后面追加 real-data 的三个字段
$json = "{"
$json += '"provider":'    + (ConvertTo-JsonString "wechat") + ","
$json += '"amount":'      + (ConvertTo-JsonString $Amount) + ","
$json += '"transNo":'     + (ConvertTo-JsonString $TransNo) + ","
$json += '"sender":'      + (ConvertTo-JsonString $Sender) + ","
$json += '"accountId":'   + (ConvertTo-JsonString $AccountId) + ","
$json += '"receivedAt":'  + $ReceivedAt + ","
$json += '"raw":'         + (ConvertTo-JsonString $Raw) + ","
$json += '"msgId":'       + (ConvertTo-JsonString $MsgId) + ","
$json += '"mchId":'       + (ConvertTo-JsonString $MchId) + ","
$json += '"shopId":'      + (ConvertTo-JsonString $ShopId) + ","
$json += '"sourceType":'  + (ConvertTo-JsonString $SourceType)
$json += "}"

$url = ($Server.TrimEnd('/')) + "/hook/payment"

Write-Host "→ POST $url" -ForegroundColor Cyan
Write-Host "  amount=$Amount kind=$Kind msgId=$MsgId" -ForegroundColor DarkGray
Write-Host "  transNo=$TransNo" -ForegroundColor DarkGray
Write-Host "  raw=$Raw" -ForegroundColor DarkGray
if ($VerbosePreference -ne "SilentlyContinue") {
    Write-Host "  body=$json" -ForegroundColor DarkGray
}

# ── 发送 ──────────────────────────────────────────────────────────────

$bytes  = [System.Text.Encoding]::UTF8.GetBytes($json)
$status = 0
$text   = ""

try {
    $resp = Invoke-WebRequest -Uri $url -Method Post -Body $bytes `
        -ContentType "application/json; charset=utf-8" `
        -TimeoutSec $TimeoutSec -UseBasicParsing
    $status = [int]$resp.StatusCode
    $text   = $resp.Content
} catch {
    $webResp = $_.Exception.Response
    if ($null -ne $webResp) {
        $status = [int]$webResp.StatusCode
        try {
            $reader = New-Object System.IO.StreamReader($webResp.GetResponseStream(), [System.Text.Encoding]::UTF8)
            $text = $reader.ReadToEnd()
        } catch { $text = "" }
    } else {
        Write-Host "✗ 请求失败：$($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  检查网关是否在 $Server 上（GET $Server/api/snapshot），或用 -Server 指定别的地址。" -ForegroundColor Yellow
        exit 1
    }
}

Write-Host "← HTTP $status" -ForegroundColor $(if ($status -ge 200 -and $status -lt 300) { "Green" } else { "Yellow" })
if ($text) { Write-Host "  $($text.Trim())" }

if ($status -lt 200 -or $status -ge 300) { exit 1 }
exit 0
