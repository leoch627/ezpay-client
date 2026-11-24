#include "AppMsg.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace wxh {

namespace {

// 找标签起始：<tag 或 <tag>
size_t FindOpenTag(const std::string& s, const std::string& tag, size_t from = 0) {
    std::string needle = "<" + tag;
    size_t p = from;
    while ((p = s.find(needle, p)) != std::string::npos) {
        const size_t after = p + needle.size();
        if (after >= s.size()) return std::string::npos;
        const char c = s[after];
        if (c == '>' || c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '/') {
            return p;
        }
        p = after;
    }
    return std::string::npos;
}

// 去除 CDATA 包裹与首尾空白
std::string StripCdata(std::string v) {
    // 去掉 <![CDATA[ ... ]]>
    size_t b = v.find("<![CDATA[");
    if (b != std::string::npos) {
        size_t e = v.find("]]>", b);
        if (e != std::string::npos) {
            v = v.substr(b + 9, e - b - 9);
        }
    }
    // 去空白
    size_t i = 0, j = v.size();
    while (i < j && (unsigned char)v[i] <= ' ') ++i;
    while (j > i && (unsigned char)v[j - 1] <= ' ') --j;
    return v.substr(i, j - i);
}

std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

// 通用：抽所有 <tag>...</tag> 的内容，返回最后一个（微信 XML 里同一 tag 可能重复，
// 而 mmreader 的 item/pub_time 是真正有用的那一个，通常在后面）
std::string ExtractLastTag(const std::string& xml, const std::string& tag) {
    std::string out;
    size_t p = 0;
    while (true) {
        size_t open = FindOpenTag(xml, tag, p);
        if (open == std::string::npos) break;

        size_t gt = xml.find('>', open);
        if (gt == std::string::npos) break;

        // 自闭合 <tag ... />
        if (gt > 0 && xml[gt - 1] == '/') {
            p = gt + 1;
            continue;
        }

        std::string closeTag = "</" + tag + ">";
        size_t close = xml.find(closeTag, gt + 1);
        if (close == std::string::npos) break;

        out = xml.substr(gt + 1, close - gt - 1);
        p = close + closeTag.size();
    }
    return StripCdata(out);
}

// 同上但返回全部
std::vector<std::string> ExtractAllTag(const std::string& xml, const std::string& tag) {
    std::vector<std::string> out;
    size_t p = 0;
    while (true) {
        size_t open = FindOpenTag(xml, tag, p);
        if (open == std::string::npos) break;
        size_t gt = xml.find('>', open);
        if (gt == std::string::npos) break;
        if (gt > 0 && xml[gt - 1] == '/') { p = gt + 1; continue; }
        std::string closeTag = "</" + tag + ">";
        size_t close = xml.find(closeTag, gt + 1);
        if (close == std::string::npos) break;
        out.push_back(StripCdata(xml.substr(gt + 1, close - gt - 1)));
        p = close + closeTag.size();
    }
    return out;
}

}  // namespace

bool AmLooksLikeAppMsgXml(const uint8_t* data, size_t len) {
    if (!data || len < 12) return false;

    // 跳过前导空白 / BOM
    size_t i = 0;
    if (len >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) i = 3;
    while (i < len && (data[i] == ' ' || data[i] == '\r' || data[i] == '\n' || data[i] == '\t')) ++i;
    if (i >= len) return false;

    if (len - i >= 5 && std::memcmp(data + i, "<?xml", 5) == 0) return true;
    if (len - i >= 4 && std::memcmp(data + i, "<msg", 4) == 0) return true;

    // 兜底：前 512 字节内出现 <appmsg
    const size_t scan = (len < 512) ? len : 512;
    for (size_t k = 0; k + 7 < scan; ++k) {
        if (std::memcmp(data + k, "<appmsg", 7) == 0) return true;
    }
    return false;
}

std::string AmExtractQueryParam(const std::string& url, const std::string& key) {
    if (url.empty() || key.empty()) return {};

    const std::string ampKey = "&" + key + "=";
    const std::string qKey = "?" + key + "=";

    size_t p = url.find(qKey);
    size_t skip = qKey.size();
    if (p == std::string::npos) {
        p = url.find(ampKey);
        skip = ampKey.size();
    }
    if (p == std::string::npos) return {};

    const size_t start = p + skip;
    size_t end = url.find_first_of("&#\"' <>\r\n", start);
    if (end == std::string::npos) end = url.size();
    return url.substr(start, end - start);
}

int64_t AmExtractAmountCents(const std::string& text) {
    if (text.empty()) return 0;

    // 金额模式，按优先级
    struct Rule {
        const char* kw;
        bool        needYuan;   // 是否需要「元」结尾
    };

    // 用状态机扫，避免依赖 std::regex（体积大且慢）
    // 目标：找到关键字后，跳过非数字非货币符号，读 \d+(\.\d{1,2})?
    const char* kws[] = {
        "收款到账", "收款金额", "到账金额", "收款", "到账", "已收款"
    };

    for (const char* kw : kws) {
        size_t p = 0;
        while ((p = text.find(kw, p)) != std::string::npos) {
            size_t i = p + std::strlen(kw);

            // 跳过中间的空白、冒号、货币符号、括号
            while (i < text.size()) {
                const unsigned char c = (unsigned char)text[i];
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
                    c == ':' || c == ')' || c == '(') {
                    ++i;
                    continue;
                }
                // UTF-8 多字节前缀（￥ U+FFE5 / ¥ U+00A5 / 其他符号）整段跳过
                if (c == 0xEF || c == 0xC2 || c == 0xE3) {
                    ++i;
                    while (i < text.size() && ((unsigned char)text[i] & 0xC0) == 0x80) ++i;
                    continue;
                }
                break;
            }

            if (i >= text.size() || !std::isdigit((unsigned char)text[i])) {
                p += std::strlen(kw);
                continue;
            }

            int64_t yuan = 0;
            size_t digits = 0;
            while (i < text.size() && std::isdigit((unsigned char)text[i])) {
                yuan = yuan * 10 + (text[i] - '0');
                if (yuan > 100000000LL) { yuan = 0; break; }
                ++i;
                ++digits;
            }
            // 整数部分可以是 0（"0.01"），只要有小数位就是合法金额
            if (digits == 0) { p += std::strlen(kw); continue; }

            int64_t cents = 0;
            if (i < text.size() && text[i] == '.') {
                ++i;
                int got = 0;
                while (i < text.size() && std::isdigit((unsigned char)text[i]) && got < 2) {
                    cents = cents * 10 + (text[i] - '0');
                    ++i;
                    ++got;
                }
                while (got < 2) { cents *= 10; ++got; }
            }

            // 必须跟「元」或者关键字本身足够明确
            bool hasYuan = false;
            for (size_t k = i; k < text.size() && k < i + 8; ++k) {
                if (std::memcmp(text.data() + k, "\xE5\x85\x83", 3) == 0) { hasYuan = true; break; }
            }

            const int64_t total = yuan * 100 + cents;
            // 合理性：0.01 ~ 100000 元
            if (total >= 1 && total <= 10000000LL) {
                if (hasYuan || std::strcmp(kw, "收款金额") == 0 ||
                    std::strcmp(kw, "到账金额") == 0) {
                    return total;
                }
                // 没有「元」也接受，只要带小数点（如 130.00）
                if (cents > 0) return total;
            }

            p += std::strlen(kw);
        }
    }
    return 0;
}

AppMsgInfo AmParseAppMsgXml(const std::string& xml) {
    AppMsgInfo info;
    if (xml.empty()) {
        info.reason = "empty xml";
        return info;
    }

    // 1) 标题：取最后一个 title（mmreader 的 item/title 才是正文）
    info.title = ExtractLastTag(xml, "title");
    info.des   = ExtractLastTag(xml, "des");

    // 2) pub_time
    {
        std::string t = ExtractLastTag(xml, "pub_time");
        if (!t.empty()) {
            info.pubTime = (int64_t)std::strtoll(t.c_str(), nullptr, 10);
        }
    }

    // 3) weapp_path —— 关键字段全在这里
    //
    // 坑：链接收款（MCH_QRCODE）一条消息里有两个 weapp_path：
    //   ① pages/mini-receipt/order-detail/...        ← 带 out_order_no / mch_id / shop_id
    //   ② pages/link-qr-code/index/index.html?...    ← 只有 shop_id / receipt_id
    // 所以必须遍历全部，取第一个真正带 out_order_no 的，不能简单取最后一个。
    {
        const std::vector<std::string> paths = ExtractAllTag(xml, "weapp_path");
        for (const auto& p : paths) {
            const std::string orderNo = AmExtractQueryParam(p, "out_order_no");
            if (orderNo.empty()) continue;

            info.outOrderNo  = orderNo;
            info.mchId       = AmExtractQueryParam(p, "mch_id");
            info.shopId      = AmExtractQueryParam(p, "shop_id");
            info.sourceType  = AmExtractQueryParam(p, "source_type");
            info.accountType = AmExtractQueryParam(p, "account_type");
            info.receiptId   = AmExtractQueryParam(p, "receipt_id");

            // source_type 形如 E_ORDER_TRADE_FROM_TYPE_SHOP_QRCODE，取尾部
            const std::string prefix = "E_ORDER_TRADE_FROM_TYPE_";
            if (info.sourceType.rfind(prefix, 0) == 0) {
                info.sourceType = info.sourceType.substr(prefix.size());
            }
            break;
        }

        // 都没带单号时，至少把 shop_id / receipt_id 留下来便于排查
        if (info.outOrderNo.empty()) {
            for (const auto& p : paths) {
                if (info.shopId.empty())    info.shopId    = AmExtractQueryParam(p, "shop_id");
                if (info.receiptId.empty()) info.receiptId = AmExtractQueryParam(p, "receipt_id");
                if (!info.shopId.empty()) break;
            }
        }
    }

    // 4) 门店名：des 里「收款门店:xxx」
    if (!info.des.empty()) {
        const char* kw = "收款门店:";
        size_t p = info.des.find(kw);
        if (p == std::string::npos) {
            // 也可能是「收款门店：」全角
            kw = "收款门店：";
            p = info.des.find(kw);
        }
        if (p != std::string::npos) {
            size_t s = p + std::strlen(kw);
            size_t e = info.des.find_first_of("\r\n", s);
            if (e == std::string::npos) e = info.des.size();
            info.storeName = info.des.substr(s, e - s);
            // 去空白
            while (!info.storeName.empty() && (unsigned char)info.storeName.front() <= ' ')
                info.storeName.erase(info.storeName.begin());
            while (!info.storeName.empty() && (unsigned char)info.storeName.back() <= ' ')
                info.storeName.pop_back();
        }
    }

    // 5) 过滤退款/转账
    const std::string lowerAll = ToLower(xml);
    const bool hasRefund = lowerAll.find("退款") != std::string::npos ||
                           lowerAll.find("已退款") != std::string::npos ||
                           lowerAll.find("撤销") != std::string::npos;
    if (hasRefund) {
        info.isRefund = true;
        info.reason = "refund/void message";
        return info;
    }

    // 6) 必须是收款类
    const bool hasPayKw = info.title.find("收款到账") != std::string::npos ||
                          info.title.find("收款") != std::string::npos ||
                          info.des.find("收款金额") != std::string::npos;
    if (!hasPayKw) {
        info.reason = "no payment keyword in title/des";
        return info;
    }

    // 7) 过滤「你付给别人」的转账通知
    if (info.title.find("转账") != std::string::npos) {
        info.reason = "transfer-out message";
        return info;
    }

    // 8) 金额：优先 title，其次 des
    info.amountCents = AmExtractAmountCents(info.title);
    if (info.amountCents <= 0) info.amountCents = AmExtractAmountCents(info.des);
    if (info.amountCents <= 0) {
        // 最后在整个 XML 里找一次「￥X.XX」
        const char* yuanSigns[] = { "\xEF\xBF\xA5", "\xC2\xA5" };  // ￥ / ¥
        for (const char* ys : yuanSigns) {
            size_t p = xml.find(ys);
            if (p == std::string::npos) continue;
            std::string tail = xml.substr(p + std::strlen(ys), 24);
            int64_t v = AmExtractAmountCents("收款金额" + tail);
            if (v > 0) { info.amountCents = v; break; }
        }
    }
    if (info.amountCents <= 0) {
        info.reason = "amount not resolved";
        return info;
    }

    // 9) 单号缺失也不能算有效 —— 没有单号无法去重
    if (info.outOrderNo.empty()) {
        info.reason = "out_order_no missing";
        return info;
    }

    info.isPayment = true;
    return info;
}

}  // namespace wxh
