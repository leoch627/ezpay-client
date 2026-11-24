#include "Detour.h"
#include "AppMsg.h"
#include "Log.h"
#include "PayParse.h"
#include "PbWalk.h"
#include "SafeRead.h"
#include "Sender.h"
#include "Status.h"

#include <windows.h>

#include <atomic>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

extern "C" uint64_t WxhTrampoline = 0;

namespace wxh {
namespace {

std::atomic<bool>     g_enabled{true};
std::atomic<uint64_t> g_lastSig{0};
std::atomic<uint64_t> g_lastTick{0};

// 进程内去重环：同一笔收款在 Hook 抖动下会被抓到多次
struct RecentRing {
    char key[64][24] = {};
    int  head  = 0;
    int  count = 0;

    bool Seen(const char* k) const {
        for (int i = 0; i < count; ++i) {
            if (std::strncmp(key[i], k, 23) == 0) return true;
        }
        return false;
    }
    void Push(const char* k) {
        _snprintf_s(key[head], 24, _TRUNCATE, "%s", k);
        head = (head + 1) % 64;
        if (count < 64) ++count;
    }
};

RecentRing g_ring;

// 从候选指针尝试抽收款事件。
// 判据从严：可读 → 像 XML/protobuf → 有收款关键词 → 有正数金额。
bool TryCaptureFromPtr(uint64_t addr, PaymentEvent* out) {
    if (addr < 0x10000 || addr > 0x7FFFFFFFFFFFull) return false;

    // 0) XML 快路径（主路径）：真实 4.x printpb 的 content 是 appmsg XML 文本。
    //    先只读前 16 字节判头，命中就直接按 XML 解析，不进 protobuf 遍历，
    //    省掉几轮 WalkProtobuf + 多次 SafeRead。
    {
        uint8_t head[16] = {0};
        if (IsReadable((void*)addr, sizeof(head)) && SafeRead((void*)addr, head, sizeof(head))) {
            if (LooksLikeAppMsgXml(head, sizeof(head))) {
                for (size_t len : {size_t(1024), size_t(4096), size_t(16384)}) {
                    if (!IsReadable((void*)addr, len)) continue;
                    std::string xml(len, '\0');
                    if (!SafeRead((void*)addr, &xml[0], len)) continue;
                    // 内存里后面可能跟垃圾，按 NUL 截断到真实结尾
                    const size_t z = xml.find('\0');
                    if (z != std::string::npos) xml.resize(z);
                    if (xml.size() < 16) continue;

                    PaymentEvent ev = ParseFromAppMsgXml(xml, "");
                    if (ev.valid) { *out = ev; return true; }
                    if (ev.reason != "not appmsg xml") return false;   // 是 XML 但被拒（退款等）
                }
                return false;   // 已确认 XML 头，不必再走 protobuf
            }
        }
    }

    // 1) 当 protobuf 试：逐级放大读取长度
    for (size_t len : {size_t(128), size_t(256), size_t(512), size_t(1024), size_t(4096)}) {
        if (!IsReadable((void*)addr, len)) break;

        std::vector<uint8_t> buf(len);
        if (!SafeRead((void*)addr, buf.data(), len)) break;
        if (!LooksLikePrintPb(buf.data(), buf.size())) continue;

        PbWalkResult walk = WalkProtobuf(buf.data(), buf.size(), 6);
        std::vector<std::string> strs;
        strs.reserve(walk.strings.size());
        for (auto& s : walk.strings) strs.push_back(s.utf8);

        PaymentEvent ev = ParseFromPb(strs, "");
        if (ev.valid) { *out = ev; return true; }
    }

    // 2) 当 C 字符串试（某些版本 printpb 路径里是 JSON/XML 文本）
    for (size_t maxLen : {size_t(512), size_t(2048)}) {
        if (!IsReadable((void*)addr, 8)) break;
        std::string s = ReadAnsiString(addr, maxLen);
        if (s.size() < 8) continue;
        PaymentEvent ev = ParseFromText(s, "");
        if (ev.valid) { *out = ev; return true; }
    }

    return false;
}

// 从栈参数再看一眼：微信 protobuf 路径常用 (ctx, msg, len) 布局，
// len 类参数本身不可读，但紧邻它的指针可以。
bool TryCaptureFromStack(uint64_t origRsp, PaymentEvent* out) {
    if (!origRsp) return false;

    for (int i = 1; i <= 8; ++i) {
        uint64_t slot = 0;
        if (!SafeRead((void*)(origRsp + i * 8), &slot, sizeof(slot))) break;
        if (slot == 0) continue;
        if (TryCaptureFromPtr(slot, out)) return true;
    }
    return false;
}

}  // namespace
}  // namespace wxh

extern "C" void WxhCapture(const RegSnapshot* regs, uint64_t origRsp) {
    using namespace wxh;

    if (!g_enabled.load(std::memory_order_relaxed)) return;
    if (!regs) return;

    auto& st = StatusBoard::Instance();
    st.IncCallback();

    // 节流：同一组寄存器 30ms 内不重复解析，避免一次调用触发多轮长扫描
    const uint64_t tick = GetTickCount64();
    const uint64_t sig = regs->rcx ^ (regs->rdx << 7) ^ (regs->r8 << 13) ^ (regs->r9 << 19);
    if (sig == g_lastSig.load(std::memory_order_relaxed) &&
        tick - g_lastTick.load(std::memory_order_relaxed) < 30) {
        return;
    }
    g_lastSig.store(sig, std::memory_order_relaxed);
    g_lastTick.store(tick, std::memory_order_relaxed);

    PaymentEvent ev;
    bool got = false;

    const uint64_t cands[] = { regs->rcx, regs->rdx, regs->r8, regs->r9,
                               regs->rdi, regs->rsi, regs->rbx, regs->rbp };
    for (uint64_t cand : cands) {
        if (cand < 0x10000) continue;
        if (TryCaptureFromPtr(cand, &ev)) { got = true; break; }
    }
    if (!got) got = TryCaptureFromStack(origRsp, &ev);
    if (!got) return;

    if (g_ring.Seen(ev.sourceKey.c_str())) {
        st.IncDedup();
        return;
    }
    g_ring.Push(ev.sourceKey.c_str());

    st.IncPayment();
    if (auto* raw = st.Raw()) raw->last_hit_at = tick;

    char amount[40];
    _snprintf_s(amount, sizeof(amount), _TRUNCATE, "%lld.%02lld",
                (long long)(ev.amountCents / 100), (long long)(ev.amountCents % 100));

    OutEvent oe;
    oe.amount    = amount;
    oe.raw       = ev.content;
    oe.transNo   = ev.transNo;
    oe.sender    = ev.sender;
    oe.accountId = ev.accountId;
    oe.atUnix    = ev.receivedAt;
    // appmsg XML 抽出的商户维度，网关据此区分收款来源
    oe.mchId      = ev.mchId;
    oe.shopId     = ev.shopId;
    oe.sourceType = ev.sourceType;

    WXH_INFO("payment captured: amount=%s sender=%s transNo=%s mch=%s shop=%s src=%s",
             oe.amount.c_str(), oe.sender.c_str(), oe.transNo.c_str(),
             oe.mchId.c_str(), oe.shopId.c_str(), oe.sourceType.c_str());

    SenderPush(oe);
}

// 采样开关定义在 wxh 内（与 Detour.h 的声明一致）。
// g_enabled 位于 wxh 的匿名 namespace，只有放进同一 namespace 才能解析。
namespace wxh {

void DetourSetEnabled(bool on) { g_enabled.store(on, std::memory_order_relaxed); }

}  // namespace wxh
