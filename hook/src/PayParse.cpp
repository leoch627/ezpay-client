#include "PayParse.h"

#include <windows.h>
#include <bcrypt.h>

#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <algorithm>

#pragma comment(lib, "bcrypt.lib")

namespace wxh {

namespace {

const char* kKeywords[] = {
    "微信支付收款", "收款到账", "二维码收款", "已收款", "收到转账",
    "已存入零钱", "微信转账", "收款成功", "收到一笔", "转入",
    "￥", "¥", "元",
};

bool IsDigit(char c) { return c >= '0' && c <= '9'; }

std::string Trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && (unsigned char)s[b] <= ' ') ++b;
    while (e > b && (unsigned char)s[e - 1] <= ' ') --e;
    return s.substr(b, e - b);
}

// ── 极简 XML 取值器 ──────────────────────────────────────────────────
// 不用 std::regex：这段跑在微信消息线程上，正则在 libstdc++ 里首次构造要分配
// 大量状态机内存，还会抛 bad_alloc 异常，钩子里不适合。手写扫描确定、零异常。

// 去 CDATA 包裹 + 去首尾空白
std::string CleanXmlValue(const std::string& v) {
    std::string s = Trim(v);
    if (s.size() >= 12 && s.compare(0, 9, "<![CDATA[") == 0) {
        const size_t endp = s.find("]]>");
        if (endp != std::string::npos && endp > 9) s = s.substr(9, endp - 9);
    }
    return Trim(s);
}

// 取 <tag>...</tag> 的文本值；未命中返回空
std::string XmlElement(const std::string& s, const char* tag) {
    const std::string open  = std::string("<") + tag + ">";
    const std::string close = std::string("</") + tag + ">";
    const size_t b = s.find(open);
    if (b == std::string::npos) return {};
    const size_t vs = b + open.size();
    const size_t e  = s.find(close, vs);
    if (e == std::string::npos) return {};
    return CleanXmlValue(s.substr(vs, e - vs));
}

// 取 name="value" / name='value' / name=value 形式（属性或裸 key=value 片段）
std::string XmlAttr(const std::string& s, const char* name) {
    const std::string key = std::string(name) + "=";
    size_t b = 0;
    while ((b = s.find(key, b)) != std::string::npos) {
        size_t vs = b + key.size();
        if (vs >= s.size()) return {};
        // 只有前面是分隔符才算独立 key（避免 mch_id 被 p_mch_id 误命中）
        if (b > 0) {
            const char prev = s[b - 1];
            if (!(prev == ' ' || prev == '<' || prev == '&' || prev == '"' ||
                  prev == '\'' || prev == '\t' || prev == '\r' || prev == '\n' ||
                  prev == ';' || prev == '/' || prev == '?' || prev == '>')) {
                b += key.size();
                continue;
            }
        }
        char quote = 0;
        if (s[vs] == '"' || s[vs] == '\'') { quote = s[vs]; ++vs; }
        size_t ve = vs;
        while (ve < s.size()) {
            const char ch = s[ve];
            if (quote) { if (ch == quote) break; }
            else if (ch == '<' || ch == '&' || ch == '"' || ch == '\'' ||
                     ch == ' ' || ch == '\r' || ch == '\n' || ch == '\t') break;
            ++ve;
        }
        if (ve > vs) return CleanXmlValue(s.substr(vs, ve - vs));
        b += key.size();
    }
    return {};
}

// 元素优先、属性兜底（真实 appmsg 两种形态都出现过）
std::string XmlField(const std::string& s, const char* tag) {
    std::string v = XmlElement(s, tag);
    if (v.empty()) v = XmlAttr(s, tag);
    return v;
}

bool ParseUInt64(const std::string& s, uint64_t* out) {
    if (s.empty() || s.size() > 20) return false;
    uint64_t v = 0;
    for (char c : s) {
        if (!IsDigit(c)) return false;
        v = v * 10 + (uint64_t)(c - '0');
    }
    *out = v;
    return true;
}

// 从 "130.00" 这类定点字符串算分
int64_t CentsFromDecimal(const std::string& s) {
    int64_t yuan = 0, cents = 0;
    size_t i = 0;
    while (i < s.size() && IsDigit(s[i])) {
        yuan = yuan * 10 + (s[i] - '0');
        if (yuan > 100000000LL) return 0;
        ++i;
    }
    if (i < s.size() && s[i] == '.') {
        ++i;
        int d = 0;
        while (i < s.size() && IsDigit(s[i]) && d < 2) {
            cents = cents * 10 + (s[i] - '0');
            ++d; ++i;
        }
        while (d < 2) { cents *= 10; ++d; }
    }
    return yuan * 100 + cents;
}

// 在 anchor 之后抓 "\d+\.\d{2}"
bool AmountAfterAnchor(const std::string& s, const char* anchor, int64_t* cents) {
    const std::string a(anchor);
    const size_t p = s.find(a);
    if (p == std::string::npos) return false;

    size_t i = p + a.size();
    // 允许中间夹 ￥/¥/空格
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == ':')) ++i;
    if (i < s.size() && ((unsigned char)s[i] == 0xA3 || (unsigned char)s[i] == 0xEF)) {
        // ￥(A3A4 GBK / EFBFA5 UTF-8) 或 ¥(C2A5 UTF-8) 的字节头，跳过整个符号
        ++i;
        while (i < s.size() && ((unsigned char)s[i] & 0x80)) {
            ++i;
            if (i < s.size() && s[i] == ' ') break;
        }
    }
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;

    const size_t ds = i;
    while (i < s.size() && IsDigit(s[i])) ++i;
    if (i == ds) return false;
    if (i < s.size() && s[i] == '.') {
        ++i;
        int d = 0;
        while (i < s.size() && IsDigit(s[i]) && d < 2) { ++i; ++d; }
    }
    const int64_t v = CentsFromDecimal(s.substr(ds, i - ds));
    if (v <= 0) return false;
    *cents = v;
    return true;
}

// 拒收：退款 / 转账 都不是收款事件
bool XmlRejected(const std::string& s) {
    if (s.find("退款") != std::string::npos) return true;
    if (s.find("转账") != std::string::npos) return true;
    return false;
}

}  // namespace

bool ContainsPaymentKeyword(const std::string& s) {
    if (s.empty()) return false;
    for (const char* kw : kKeywords) {
        if (s.find(kw) != std::string::npos) return true;
    }
    return false;
}

int64_t ParseAmountCents(const std::string& in) {
    const std::string s = Trim(in);
    if (s.empty()) return 0;

    // 找第一个数字起点
    size_t i = 0;
    while (i < s.size() && !IsDigit(s[i])) ++i;
    if (i >= s.size()) return 0;

    // 整数部分
    int64_t yuan = 0;
    size_t start = i;
    while (i < s.size() && IsDigit(s[i])) {
        yuan = yuan * 10 + (s[i] - '0');
        if (yuan > 100000000LL) return 0;   // 超过 1 亿，判为误抓
        ++i;
    }
    (void)start;

    int64_t cents = 0;
    if (i < s.size() && s[i] == '.') {
        ++i;
        int digits = 0;
        while (i < s.size() && IsDigit(s[i]) && digits < 2) {
            cents = cents * 10 + (s[i] - '0');
            ++digits;
            ++i;
        }
        while (digits < 2) { cents *= 10; ++digits; }
    }

    // 单位是“分”
    const size_t unitPos = s.find("分");
    if (unitPos != std::string::npos && s.find("元") == std::string::npos) {
        return yuan;
    }

    return yuan * 100 + cents;
}

std::string ExtractTransNo(const std::string& s) {
    size_t i = 0;
    while (i < s.size()) {
        if (!IsDigit(s[i])) { ++i; continue; }
        size_t j = i;
        while (j < s.size() && IsDigit(s[j])) ++j;
        const size_t n = j - i;
        if (n >= 18 && n <= 32) return s.substr(i, n);
        i = j;
    }
    return {};
}

std::string Sha1Short(const std::string& data) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h  = nullptr;
    std::string out;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr, 0) != 0) return out;

    DWORD objLen = 0, cb = 0, hashLen = 0;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0) != 0 ||
        BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &cb, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return out;
    }

    std::vector<UCHAR> obj(objLen);
    std::vector<UCHAR> digest(hashLen);
    if (BCryptCreateHash(alg, &h, obj.data(), objLen, nullptr, 0, 0) == 0) {
        BCryptHashData(h, (PUCHAR)data.data(), (ULONG)data.size(), 0);
        BCryptFinishHash(h, digest.data(), hashLen, 0);
        BCryptDestroyHash(h);

        char buf[4];
        for (int i = 0; i < 8 && i < (int)hashLen; ++i) {
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%02x", digest[i]);
            out += buf;
        }
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return out;
}

std::string MakeSourceKey(const std::string& provider,
                          const std::string& transNo,
                          const std::string& sender,
                          int64_t amountCents,
                          int64_t receivedAtSec) {
    char raw[512];
    if (!transNo.empty()) {
        _snprintf_s(raw, sizeof(raw), _TRUNCATE, "%s|%s|%lld",
                    provider.c_str(), transNo.c_str(), (long long)amountCents);
    } else {
        // 无单号：退化为 发送方+金额+秒级时间，同一秒同人同额会被判重
        _snprintf_s(raw, sizeof(raw), _TRUNCATE, "%s|%s|%lld|%lld",
                    provider.c_str(), sender.c_str(),
                    (long long)amountCents, (long long)receivedAtSec);
    }
    const std::string h = Sha1Short(raw);
    return h.empty() ? std::string(raw) : h;
}

// ── appmsg XML 主路径 ────────────────────────────────────────────────

bool LooksLikeAppMsgXml(const uint8_t* data, size_t len) {
    if (!data || len < 5) return false;

    size_t i = 0;
    // 跳过 UTF-8 BOM
    if (len >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) i = 3;
    // 跳过前导空白
    while (i < len && (data[i] == ' ' || data[i] == '\r' || data[i] == '\n' || data[i] == '\t')) ++i;
    if (i >= len) return false;

    const char* p = reinterpret_cast<const char*>(data + i);
    const size_t n = len - i;

    if (n >= 5 && std::memcmp(p, "<?xml", 5) == 0) return true;
    if (n >= 4 && std::memcmp(p, "<msg", 4) == 0) return true;
    // 少数版本外层还包了 <appmsg>
    if (n >= 7 && std::memcmp(p, "<appmsg", 7) == 0) return true;
    return false;
}

PaymentEvent ParseFromAppMsgXml(const std::string& xml, const std::string& accountHint) {
    PaymentEvent ev;
    ev.accountId = accountHint;
    ev.receivedAt = (int64_t)time(nullptr);

    if (xml.size() < 16) { ev.reason = "xml too short"; return ev; }
    if (!LooksLikeAppMsgXml(reinterpret_cast<const uint8_t*>(xml.data()), xml.size())) {
        ev.reason = "not appmsg xml";
        return ev;
    }

    // 只看 <appmsg> 段，减少误命中（外层还有 sysmsg/msgsource 等）
    std::string body = xml;
    const size_t ab = xml.find("<appmsg");
    if (ab != std::string::npos) body = xml.substr(ab);

    const std::string title = XmlField(body, "title");
    const std::string des   = XmlField(body, "des");

    // 判据 1：必须含收款语义
    const bool hasKeyword =
        title.find("收款到账") != std::string::npos ||
        title.find("收款金额") != std::string::npos ||
        body.find("收款到账")  != std::string::npos ||
        body.find("收款金额")  != std::string::npos;
    if (!hasKeyword) {
        ev.reason = "no 收款到账/收款金额 in appmsg";
        return ev;
    }

    // 判据 2：退款/转账一律不是收款
    if (XmlRejected(title) || XmlRejected(body)) {
        ev.reason = "rejected: 退款/转账";
        return ev;
    }

    // 金额：title 是权威字段，必须优先于整段 body。
    // （若先扫 body，<des> 里的旧文案会抢在 title 之前命中，导致取错金额）
    int64_t cents = 0;
    if (!AmountAfterAnchor(title, "收款到账", &cents) &&
        !AmountAfterAnchor(title, "收款金额", &cents) &&
        !AmountAfterAnchor(des,   "收款到账", &cents) &&
        !AmountAfterAnchor(des,   "收款金额", &cents) &&
        !AmountAfterAnchor(body,  "收款到账", &cents) &&
        !AmountAfterAnchor(body,  "收款金额", &cents)) {
        // 兜底：title/des 里任意 "X.XX元"
        const std::string* srcs[] = { &title, &des, &body };
        for (const auto* s : srcs) {
            const size_t yp = s->find("元");
            if (yp == std::string::npos) continue;
            // 从 "元" 往前找数字段
            size_t e = yp;
            while (e > 0 && (IsDigit((*s)[e - 1]) || (*s)[e - 1] == '.')) --e;
            const std::string num = s->substr(e, yp - e);
            const int64_t v = CentsFromDecimal(num);
            if (v > 0 && v < 100000000LL) { cents = v; break; }
        }
    }
    if (cents <= 0) { ev.reason = "amount not resolved"; return ev; }

    // 单号：out_order_no= / <out_order_no>（真实报文两种都出现）
    ev.transNo = XmlField(body, "out_order_no");
    if (ev.transNo.size() < 16 || ev.transNo.size() > 40) {
        const std::string alt = ExtractTransNo(body);
        ev.transNo = (alt.size() >= 16) ? alt : std::string();
    }

    ev.mchId      = XmlField(body, "mch_id");
    ev.shopId     = XmlField(body, "shop_id");
    ev.sourceType = XmlField(body, "source_type");
    // source_type=E_ORDER_TRADE_FROM_TYPE_XXX → 只留后缀
    const std::string kPrefix = "E_ORDER_TRADE_FROM_TYPE_";
    if (ev.sourceType.compare(0, kPrefix.size(), kPrefix) == 0) {
        ev.sourceType = ev.sourceType.substr(kPrefix.size());
    }

    {
        const std::string pt = XmlField(body, "pub_time");
        uint64_t v = 0;
        if (ParseUInt64(pt, &v) && v > 1600000000ull && v < 4102444800ull) {
            ev.pubTime = (int64_t)v;
            ev.receivedAt = ev.pubTime;
        }
    }

    ev.content     = title.empty() ? body.substr(0, 512) : title;
    ev.amountCents = cents;

    // sender：收款报文里通常没有付款方昵称，title 前缀里的 "[店员消息]" 不是人名。
    // 保留空串，让上层按 accountId 记账。
    ev.sender = XmlField(body, "nickname");

    ev.sourceKey = MakeSourceKey(ev.provider, ev.transNo, ev.sender, ev.amountCents, ev.receivedAt);
    ev.valid = true;
    return ev;
}

PaymentEvent ParseFromPb(const std::vector<std::string>& strings,
                        const std::string& accountHint) {
    // 主路径：先在候选字符串里找 appmsg XML（真实 4.x printpb 走这条）
    for (const auto& s : strings) {
        if (s.size() < 16) continue;
        if (s.find("收款到账") == std::string::npos &&
            s.find("收款金额") == std::string::npos) continue;
        if (!LooksLikeAppMsgXml(reinterpret_cast<const uint8_t*>(s.data()), s.size())) continue;

        PaymentEvent x = ParseFromAppMsgXml(s, accountHint);
        if (x.valid) return x;
    }

    // 兜底：老的纯文本启发式
    PaymentEvent ev;
    ev.accountId = accountHint;
    ev.receivedAt = (int64_t)time(nullptr);

    // 找出含收款关键词的文本，作为 content 主体
    std::string bestContent;
    std::string bestSender;

    for (const auto& s : strings) {
        if (s.size() < 4) continue;
        if (!ContainsPaymentKeyword(s)) continue;
        if (s.size() > bestContent.size()) bestContent = s;
    }

    // sender：通常是含关键词文本之外、长度 1~32 的中文串
    // 用「与 content 不同 + 无数字 + 长度合适」做粗筛，取第一个
    for (const auto& s : strings) {
        if (s == bestContent) continue;
        if (s.size() < 2 || s.size() > 48) continue;
        bool hasDigit = false, hasCjk = false;
        for (unsigned char c : s) {
            if (c >= '0' && c <= '9') hasDigit = true;
            if (c >= 0xE0) hasCjk = true;
        }
        if (hasDigit) continue;
        if (!hasCjk) continue;
        if (ContainsPaymentKeyword(s)) continue;
        // 排除明显是系统/状态文案的
        if (s.find("微信") != std::string::npos) continue;
        if (s.find("支付") != std::string::npos) continue;
        bestSender = s;
        break;
    }

    if (bestContent.empty()) {
        ev.reason = "no payment keyword in strings";
        return ev;
    }

    ev.content = bestContent;
    ev.sender  = bestSender;
    ev.amountCents = ParseAmountCents(bestContent);
    if (ev.amountCents <= 0) {
        // 从其余字符串里再找一次金额
        for (const auto& s : strings) {
            const int64_t v = ParseAmountCents(s);
            if (v > 0 && v < 100000000LL) { ev.amountCents = v; break; }
        }
    }
    if (ev.amountCents <= 0) {
        ev.reason = "amount not resolved";
        return ev;
    }

    ev.transNo = ExtractTransNo(bestContent);
    if (ev.transNo.empty()) {
        for (const auto& s : strings) {
            ev.transNo = ExtractTransNo(s);
            if (!ev.transNo.empty()) break;
        }
    }

    ev.sourceKey = MakeSourceKey(ev.provider, ev.transNo, ev.sender, ev.amountCents, ev.receivedAt);
    ev.valid = true;
    return ev;
}

PaymentEvent ParseFromText(const std::string& text, const std::string& accountHint) {
    // 主路径：如果是 appmsg XML，直接走 XML 解析
    if (LooksLikeAppMsgXml(reinterpret_cast<const uint8_t*>(text.data()), text.size())) {
        PaymentEvent x = ParseFromAppMsgXml(text, accountHint);
        if (x.valid) return x;
        // XML 但判定失败（退款/无金额）—— 直接把原因带出去，不要再退回关键字链，
        // 否则「退款」报文会被下面的 ContainsPaymentKeyword 当成收款。
        if (x.reason != "not appmsg xml") return x;
    }

    PaymentEvent ev;
    ev.accountId  = accountHint;
    ev.receivedAt = (int64_t)time(nullptr);

    if (text.empty()) { ev.reason = "empty text"; return ev; }
    if (!ContainsPaymentKeyword(text)) { ev.reason = "no payment keyword"; return ev; }

    ev.content = text;
    ev.amountCents = ParseAmountCents(text);
    if (ev.amountCents <= 0) { ev.reason = "amount not resolved"; return ev; }

    ev.transNo = ExtractTransNo(text);
    ev.sourceKey = MakeSourceKey(ev.provider, ev.transNo, ev.sender, ev.amountCents, ev.receivedAt);
    ev.valid = true;
    return ev;
}

}  // namespace wxh
