// AppMsg.h —— 微信 appmsg XML 解析（基于真实样本反推）
//
// 真实样本（来自 monitor.db 已解密的 277 笔记录）长这样：
//
//   <?xml version="1.0"?>
//   <msg>
//     <appmsg appid="" sdkver="0">
//       <title><![CDATA[[店员消息]收款到账130.00元]]></title>
//       <des><![CDATA[收款金额￥130.00
//   收款门店:leochang
//   收款说明:收款
//   说明:已存入店长leochang(**店)的经营账户]]></des>
//       <type>5</type>
//       <mmreader><category><topnew><item>
//         <pub_time>1794907986</pub_time>
//         <weapp_path><![CDATA[pages/mini-receipt/order-detail/order-detail.html
//           ?account_type=E_MINI_RECEIPT_EACCOUNT_TYPE_SJT
//           &source_type=E_ORDER_TRADE_FROM_TYPE_MCH_QRCODE
//           &shop_id=43030953
//           &out_order_no=TON3UZ-00BT0SR-0DBF4UR-KP94HZ8I
//           &operator_role=E_MINI_RECEIPT_OPERATOR_ROLE_ASSISTANT
//           &mch_id=805242195
//           &from=mini_receipt_assistant_msg_detail]]></weapp_path>
//       </item></topnew></category></mmreader>
//     </appmsg>
//   </msg>
//
// 两种通知：source_type=SHOP_QRCODE（经营码，out_order_no 32 位数字）
//           source_type=MCH_QRCODE （链接收款，out_order_no 分段带横杠）
//
// 同一笔收款会同时产生「[店员消息]收款到账」与「经营码收款到账通知」两条 appmsg，
// 且两者 mch_id/shop_id 相同、out_order_no 相同 —— 必须按 out_order_no 去重。
#pragma once

#include <cstdint>
#include <string>

namespace wxh {

struct AppMsgInfo {
    bool        isPayment   = false;   // 是否判定为收款通知
    bool        isRefund    = false;   // 退款/撤销，必须过滤
    int64_t     amountCents = 0;
    std::string title;
    std::string des;
    std::string outOrderNo;      // 微信侧订单号
    std::string mchId;           // 微信支付商户号
    std::string shopId;          // 微信收款商业版门店 ID
    std::string sourceType;      // SHOP_QRCODE | MCH_QRCODE | ...
    std::string accountType;     // E_MINI_RECEIPT_EACCOUNT_TYPE_SJT
    std::string receiptId;       // 链接收款时的收据 ID
    std::string storeName;       // 收款门店
    int64_t     pubTime  = 0;    // unix 秒
    std::string reason;          // 未判定为收款时的原因
};

// 快速判定：这段 buffer 是不是微信 appmsg XML
// 判据：以 '<?xml' 或 '<msg' 开头（可带前导空白），或包含 '<appmsg'
bool AmLooksLikeAppMsgXml(const uint8_t* data, size_t len);

// 完整解析。输入是 XML 文本（UTF-8）。
AppMsgInfo AmParseAppMsgXml(const std::string& xml);

// 从任意文本里提取收款金额（分）。支持：
//   「收款到账130.00元」「收款金额￥130.00」「收款金额:130.00」
//   「收款到账 ¥130.00」「到账130.00」
int64_t AmExtractAmountCents(const std::string& text);

// 从 URL 查询串里抽取指定 key 的值（用于解析 weapp_path）
std::string AmExtractQueryParam(const std::string& url, const std::string& key);

}  // namespace wxh
