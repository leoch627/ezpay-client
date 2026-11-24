#include "Sender.h"
#include "Log.h"
#include "Status.h"

#include <windows.h>
#include <winhttp.h>

#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

#pragma comment(lib, "winhttp.lib")

namespace wxh {

namespace {

std::mutex              g_mu;
std::condition_variable g_cv;
std::deque<OutEvent>    g_q;
bool                    g_running = false;
std::wstring            g_host;      // 127.0.0.1
std::wstring            g_path;      // /hook/payment
INTERNET_PORT           g_port = 29731;

// 线程持有器：**必须**有析构兜底 detach。
// 进程退出时 DllMain 走 lpReserved != nullptr 分支，我们不主动清理；
// 若这里是个裸 static std::thread，那么 DLL 卸载阶段的静态析构会撞上
// 一个仍然 joinable 的 thread，libc++ 直接 std::terminate → 微信退出时崩溃。
// 所以：先让 worker 退出循环，join 得到就 join，拿不到就 detach，绝不 terminate。
struct ThreadHolder {
    std::thread t;
    ~ThreadHolder() {
        if (t.joinable()) t.detach();
    }
};

ThreadHolder g_worker;

// 队列上限：网关长时间不在线时，宁可丢最旧的也不让微信内存涨
constexpr size_t kQueueCap = 512;

std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "\\u%04X", c);
                    out += buf;
                } else {
                    out += (char)c;   // UTF-8 原样透传，Go 侧按 UTF-8 解析
                }
        }
    }
    return out;
}

std::string BuildJson(const OutEvent& ev) {
    char head[512];
    _snprintf_s(head, sizeof(head), _TRUNCATE,
                "{\"provider\":\"wechat\",\"amount\":\"%s\",\"transNo\":\"%s\","
                "\"sender\":\"%s\",\"accountId\":\"%s\",\"receivedAt\":%lld,\"raw\":\"",
                JsonEscape(ev.amount).c_str(),
                JsonEscape(ev.transNo).c_str(),
                JsonEscape(ev.sender).c_str(),
                JsonEscape(ev.accountId).c_str(),
                (long long)ev.atUnix);

    std::string body = std::string(head) + JsonEscape(ev.raw) + "\"";
    // appmsg XML 抽出的商户信息，字段为空时省掉，保持旧网关兼容
    if (!ev.mchId.empty())      body += ",\"mchId\":\"" + JsonEscape(ev.mchId) + "\"";
    if (!ev.shopId.empty())     body += ",\"shopId\":\"" + JsonEscape(ev.shopId) + "\"";
    if (!ev.sourceType.empty()) body += ",\"sourceType\":\"" + JsonEscape(ev.sourceType) + "\"";
    body += "}";
    return body;
}

bool HttpPost(const std::string& body, std::string* err) {
    if (g_host.empty()) { if (err) *err = "host empty"; return false; }

    HINTERNET ses = WinHttpOpen(L"WxPayHook/1",
                                WINHTTP_ACCESS_TYPE_NO_PROXY,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) { if (err) *err = "WinHttpOpen failed"; return false; }

    bool ok = false;
    HINTERNET con = nullptr, req = nullptr;

    con = WinHttpConnect(ses, g_host.c_str(), g_port, 0);
    if (!con) { if (err) *err = "WinHttpConnect failed"; goto done; }

    req = WinHttpOpenRequest(con, L"POST", g_path.c_str(), nullptr,
                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!req) { if (err) *err = "WinHttpOpenRequest failed"; goto done; }

    {
        // 关键：超时要短。这里宁可丢一条事件也不能拖住投递线程。
        DWORD timeout = 3000;
        WinHttpSetOption(req, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(req, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(req, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    }

    {
        const wchar_t* hdr = L"Content-Type: application/json\r\n";
        if (!WinHttpSendRequest(req, hdr, (DWORD)-1L,
                                (LPVOID)body.data(), (DWORD)body.size(),
                                (DWORD)body.size(), 0)) {
            if (err) *err = "WinHttpSendRequest failed";
            goto done;
        }
    }
    if (!WinHttpReceiveResponse(req, nullptr)) {
        if (err) *err = "WinHttpReceiveResponse failed";
        goto done;
    }

    {
        DWORD status = 0, len = sizeof(status);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &len, WINHTTP_NO_HEADER_INDEX);
        ok = (status >= 200 && status < 300);
        if (!ok && err) {
            char buf[64];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "http %lu", status);
            *err = buf;
        }
    }

done:
    if (req) WinHttpCloseHandle(req);
    if (con) WinHttpCloseHandle(con);
    WinHttpCloseHandle(ses);
    return ok;
}

void WorkerLoop() {
    SetThreadDescription(GetCurrentThread(), L"wxhook-sender");

    while (true) {
        OutEvent ev;
        {
            std::unique_lock<std::mutex> lk(g_mu);
            g_cv.wait(lk, [] { return !g_running || !g_q.empty(); });
            if (!g_running && g_q.empty()) return;
            ev = g_q.front();
            g_q.pop_front();
        }

        const std::string body = BuildJson(ev);
        std::string err;
        const bool ok = HttpPost(body, &err);
        StatusBoard::Instance().IncPost(ok);
        if (ok) {
            WXH_INFO("posted payment amount=%s transNo=%s", ev.amount.c_str(), ev.transNo.c_str());
        } else {
            WXH_WARN("post failed: %s | body=%.200s", err.c_str(), body.c_str());
        }
    }
}

}  // namespace

void SenderStart(const std::wstring& endpoint) {
    // endpoint 形如 L"127.0.0.1:29731/hook/payment"
    std::wstring e = endpoint;
    const size_t slash = e.find(L'/');
    if (slash != std::wstring::npos) {
        g_path = e.substr(slash);
        e = e.substr(0, slash);
    } else {
        g_path = L"/hook/payment";
    }
    const size_t colon = e.find(L':');
    if (colon != std::wstring::npos) {
        g_host = e.substr(0, colon);
        g_port = (INTERNET_PORT)_wtoi(e.c_str() + colon + 1);
    } else {
        g_host = e;
    }

    std::lock_guard<std::mutex> lk(g_mu);
    if (g_running) return;
    if (g_worker.t.joinable()) g_worker.t.join();   // 上一轮已退出，回收掉
    g_running = true;
    g_worker.t = std::thread(WorkerLoop);
    WXH_INFO("sender started -> %ls", endpoint.c_str());
}

void SenderStop() {
    {
        std::lock_guard<std::mutex> lk(g_mu);
        if (!g_running) return;
        g_running = false;
    }
    g_cv.notify_all();
    if (g_worker.t.joinable()) g_worker.t.join();
}

void SenderPush(const OutEvent& ev) {
    {
        std::lock_guard<std::mutex> lk(g_mu);
        if (!g_running) return;
        if (g_q.size() >= kQueueCap) {
            g_q.pop_front();
            WXH_WARN("sender queue full, dropped oldest");
        }
        g_q.push_back(ev);
    }
    g_cv.notify_one();
}

}  // namespace wxh
