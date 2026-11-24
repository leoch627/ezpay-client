// PayParse.h —— 从 printpb 抽取收款语义
//
// 不做字段号硬绑定。判定链条：
//   1) 文本里出现收款关键词（"收到转账"/"微信支付收款"/"二维码收款"/"已收款"…）
//   2) 抽出金额（元 或 分）
//   3) 抽出转账单号（长串数字）
// 任一环节失败不回事件，只记日志。
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace wxh {

struct PaymentEvent {
    std::string provider   = "wechat";
    std::string accountId;      // 收款账号 wxid
    std::string sender;         // 付款方昵称
    std::string content;        // 原始文案
    std::string transNo;        // 转账单号
    std::string sourceKey;      // 幂等键
    int64_t     amountCents = 0;
    int64_t     receivedAt  = 0;

    // ── appmsg XML 专用字段（真实微信 4.x printpb 里是 XML 文本，不是 protobuf）──
    std::string mchId;          // mch_id=
    std::string shopId;         // shop_id=
    std::string sourceType;     // source_type=E_ORDER_TRADE_FROM_TYPE_xxx 里的 xxx
    int64_t     pubTime     = 0;// <pub_time> 秒级时间戳

    bool        valid       = false;
    std::string reason;         // 判定失败原因
};

// 主路径：从微信 appmsg XML 抽收款事件。
// 真实 content 形如：
//   <?xml version="1.0"?><msg><appmsg appid="" sdkver="0"><title>[店员消息]收款到账130.00元</title>
//   ...<out_order_no>...</out_order_no>...<mch_id>..</mch_id><shop_id>..</shop_id>
//   <source_type>E_ORDER_TRADE_FROM_TYPE_xxx</source_type><pub_time>1699999999</pub_time>...</appmsg></msg>
// 判据：含「收款到账」或「收款金额」，且不含「退款」/「转账」。
PaymentEvent ParseFromAppMsgXml(const std::string& xml, const std::string& accountHint);

// 内存字节是否像 appmsg XML（以 "<?xml" 或 "<msg" 开头）
bool LooksLikeAppMsgXml(const uint8_t* data, size_t len);

// 从 protobuf 遍历结果装配事件（兜底路径，主路径已改为 ParseFromAppMsgXml）
PaymentEvent ParseFromPb(const std::vector<std::string>& strings,
                         const std::string& accountHint);

// 从纯文本装配（兜底：某些版本 printpb 里是一整段 JSON/XML）
// 现在会先尝试按 XML 解析，失败再走纯关键字链。
PaymentEvent ParseFromText(const std::string& text, const std::string& accountHint);

// 金额解析：
//   "12.34" / "¥12.34" / "12.34元" -> 1234
//   "1234分" -> 1234
int64_t ParseAmountCents(const std::string& s);

// 从任意文本里抓 18~32 位连续数字当单号
std::string ExtractTransNo(const std::string& s);

bool ContainsPaymentKeyword(const std::string& s);

// 生成幂等键
std::string MakeSourceKey(const std::string& provider,
                          const std::string& transNo,
                          const std::string& sender,
                          int64_t amountCents,
                          int64_t receivedAtSec);

// 计算 SHA1 前 8 字节 hex（16 字符）
std::string Sha1Short(const std::string& data);

}  // namespace wxh
