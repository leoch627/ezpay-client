#include "Hook.h"
#include "Detour.h"
#include "Log.h"
#include "Pattern.h"
#include "SafeRead.h"
#include "Sender.h"
#include "Status.h"
#include "Trampoline.h"

#include <windows.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <thread>
#include <vector>

namespace wxh {

namespace {

std::atomic<bool> g_installing{false};
InlineHook        g_hook;
// 注意：投递端点只在 DllMain.cpp 的 ReadEndpoint() 里定义一次。
// 这里曾有 g_endpoint 与 ReadEndpointFromEnv() 两个死副本，
// 改端口时容易只改一处，已删除。

// 引导线程存活标记。DLL 卸载时先把它清掉并等它退出，
// 否则 detached 的引导线程会在代码段 unmap 之后继续跑 → 野指令崩溃。
std::atomic<bool> g_bootStop{false};
std::atomic<bool> g_bootAlive{false};

// 已知版本最低要求（与逆向包里的 requiredVersion 一致）
// 注意：WxPackVersion 在 wxhook_abi.h 里是 static inline（C 兼容，不能标 constexpr），
// 所以这里只能用 const，不能 constexpr。
const uint32_t kRequiredVersion = WxPackVersion(4, 1, 10, 31);

// ── printpb 特征码 ───────────────────────────────────────────────────
//
// 这些特征码是 2026-11 从真实 Weixin.dll 4.1.12.53 里提取并**验证唯一**的，
// 不是拍脑袋写的通用序言。提取方法见 scripts/find_printpb.py 与 extract_signatures.py：
//
//   1) 在 .rdata 找 "weapp_path" 字符串（收款 appmsg 独有，微信全模块只出现 1 次）
//   2) 在 .text 找引用该 RVA 的 lea/mov rip-relative 指令 → 得到 xref
//   3) 由 xref 回溯到函数入口（跳过 CC 填充）
//   4) 取入口字节逐步加长，直到在 113 MB 的 .text 里**只命中自身 1 次**
//
// 实测结论（scripts/verify_signatures.py 可复现）：
//   原来的 "48 8D 81 ?? ?? ?? ?? C3"  → 104 处命中（通用序言，不可用）
//   原来的 "48 8D 41 ?? C3"           → 65 处命中（不可用）
//   下面的两条                       → 各 1 处命中（唯一）
//
// 代价：特征码长度 28~32 字节，比通用序言长，但这是唯一性换来的，值得。
// 且每条都带预期 RVA，扫描命中后要额外校验 RVA 是否接近预期，
// 防止跨小版本误命中（版本变化时 RVA 会漂，但不会漂太远）。
//
const Pattern kPrintPbPatterns[] = {
    // Weixin.dll 4.1.12.53, 引用 weapp_path 的函数 A
    { "weapp_path.A",
      "CC 0F 1F 40 00 48 89 54 24 10 55 41 57 41 56 41 54 56 57 53 48 83 EC 20 48 8D 6A 70 48 8B 4D E8",
      1, 0x48BE1BB },

    // Weixin.dll 4.1.12.53, 引用 weapp_path 的函数 B
    { "weapp_path.B",
      "CC CC CC CC CC CC CC CC CC CC CC 41 56 56 57 53 48 83 EC 38 48 89 CE 48 89 54 24 30",
      1, 0x48BEAA5 },
};

std::wstring Widen(const std::string& s) {
    std::wstring w;
    w.reserve(s.size());
    for (char c : s) w += (wchar_t)(unsigned char)c;
    return w;
}

HMODULE FindWeixinModule() {
    // 4.x 是 Weixin.dll，3.x 是 WeChatWin.dll
    for (const wchar_t* name : { L"Weixin.dll", L"WeChatWin.dll" }) {
        HMODULE m = GetModuleHandleW(name);
        if (m) return m;
    }
    return nullptr;
}

std::string ShortHex(uint64_t v) {
    char b[32];
    _snprintf_s(b, sizeof(b), _TRUNCATE, "0x%llX", (unsigned long long)v);
    return b;
}

}  // namespace

uint32_t DetectWeChatVersion() {
    // Software\Tencent\Weixin 下可能有 Version 或 InstallPath 里的版本信息
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Tencent\\Weixin", 0, KEY_READ, &key) != ERROR_SUCCESS) {
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Tencent\\Weixin", 0,
                      KEY_READ | KEY_WOW64_64KEY, &key);
    }
    if (!key) return 0;

    DWORD ver = 0, cb = sizeof(ver), type = 0;
    LONG rc = RegQueryValueExW(key, L"Version", nullptr, &type, (LPBYTE)&ver, &cb);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || type != REG_DWORD) return 0;
    return (uint32_t)ver;
}

std::string BestEffortAccountId() {
    // 微信 wxid 在多个位置出现；这里用最稳的一处：
    // 进程命令行里通常带 wxid_ 前缀的账号目录，或者环境里的 USERPROFILE 下的 Documents\WeChat Files\wxid_xxx
    // 拿不到就返回空，上层不阻塞。
    wchar_t profile[MAX_PATH] = {0};
    if (GetEnvironmentVariableW(L"USERPROFILE", profile, MAX_PATH) > 0) {
        std::wstring p(profile);
        p += L"\\Documents\\WeChat Files";
        // 枚举子目录找 wxid_ 前缀
        std::wstring pat = p + L"\\wxid_*";
        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW(pat.c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) {
            std::string out;
            for (wchar_t* c = fd.cFileName; *c && out.size() < 64; ++c) {
                if (*c < 0x80) out += (char)*c;
            }
            FindClose(h);
            return out;
        }
        // 新版 4.x 用 xwechat_files
        p = std::wstring(profile) + L"\\Documents\\xwechat_files";
        pat = p + L"\\wxid_*";
        h = FindFirstFileW(pat.c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) {
            std::string out;
            for (wchar_t* c = fd.cFileName; *c && out.size() < 64; ++c) {
                if (*c < 0x80) out += (char)*c;
            }
            FindClose(h);
            return out;
        }
    }
    return {};
}

bool InstallHooks() {
    bool expected = false;
    if (!g_installing.compare_exchange_strong(expected, true)) return IsInstalled();

    struct Guard {
        std::atomic<bool>& f;
        ~Guard() { f.store(false); }
    } guard{g_installing};

    auto& st = StatusBoard::Instance();

    HMODULE mod = FindWeixinModule();
    if (!mod) {
        st.SetState(WXHOOK_STATE_MODULE_MISSING, "Weixin.dll not loaded in this process");
        WXH_WARN("Weixin.dll not loaded; nothing to hook");
        return false;
    }

    // 模块范围
    uint64_t base = (uint64_t)mod;
    uint64_t size = 0;
    {
        auto* dos = (IMAGE_DOS_HEADER*)mod;
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            auto* nt = (IMAGE_NT_HEADERS*)((uint8_t*)mod + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) size = nt->OptionalHeader.SizeOfImage;
        }
    }
    st.SetModule(base, size);
    st.SetVersion(DetectWeChatVersion(), kRequiredVersion);

    WXH_INFO("Weixin.dll base=%s size=%llu",
             ShortHex(base).c_str(), (unsigned long long)size);

    // 版本闸门：低于要求版本时仍然尝试，但状态里标出来
    const uint32_t ver = DetectWeChatVersion();
    if (ver != 0 && ver < kRequiredVersion) {
        char msg[128];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                    "WeChat version 0x%08X below required 0x%08X; hook may not work",
                    ver, kRequiredVersion);
        st.SetState(WXHOOK_STATE_VERSION_UNSUPPORTED, msg);
        WXH_WARN("%s", msg);
    }

    // 扫描
    st.SetState(WXHOOK_STATE_SCANNING, "scanning Weixin.dll for printpb");
    std::vector<Pattern> pats(std::begin(kPrintPbPatterns), std::end(kPrintPbPatterns));

    // 扫两轮：第一轮全量；没中就等 1.5s 再扫（模块可能还没完全重定位）
    ScanHit hit{};
    for (int round = 0; round < 2 && !hit.addr; ++round) {
        if (round > 0) Sleep(1500);
        hit = ScanModule(mod, pats);
    }

    if (!hit.addr) {
        st.SetState(WXHOOK_STATE_PATTERN_MISS,
                    "no printpb signature matched; WeChat build may be unsupported");
        WXH_WARN("pattern scan miss (tried %zu signatures)", pats.size());
        return false;
    }

    WXH_INFO("pattern hit: %s @ %s (rva=0x%X, rvaOk=%d, dist=0x%X)",
             hit.pat->id, ShortHex((uint64_t)hit.addr).c_str(),
             hit.rva, (int)hit.rvaOk, hit.rvaDist);

    // ★ 安全闸门：特征命中但 RVA 偏离预期太远 → 说明是别处的同构代码，
    //   绝对不钩。钩错的后果是微信崩溃，比"这个版本不支持"严重得多。
    if (!hit.rvaOk) {
        char msg[192];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                    "signature matched at RVA 0x%X but expected ~0x%X (dist 0x%X > tolerance); "
                    "refusing to hook to avoid crashing WeChat",
                    hit.rva, hit.pat->expectedRva, hit.rvaDist);
        st.SetState(WXHOOK_STATE_VERSION_UNSUPPORTED, msg);
        WXH_ERR("%s", msg);
        return false;
    }

    // 前导校验
    std::string why;
    if (!InlineHook::ValidatePrologue(hit.addr, 14, &why)) {
        char msg[160];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE, "unsafe prologue: %s", why.c_str());
        st.SetState(WXHOOK_STATE_PROLOGUE_BAD, msg);
        WXH_WARN("%s", msg);
        return false;
    }

    // 装钩子
    std::string err;
    if (!g_hook.Install(hit.addr, (uint8_t*)&WxhDetourStub, &err)) {
        char msg[160];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE, "install failed: %s", err.c_str());
        st.SetState(WXHOOK_STATE_PATCH_FAIL, msg);
        WXH_ERR("%s", msg);
        return false;
    }

    WxhTrampoline = (uint64_t)g_hook.Trampoline();

    st.SetPattern(hit.pat->id, (uint64_t)hit.addr, (uint64_t)g_hook.Trampoline());
    st.SetState(WXHOOK_STATE_INSTALLED, "printpb hook installed");

    WXH_INFO("==== hook ready: target=%s tramp=%s ====",
             ShortHex((uint64_t)hit.addr).c_str(),
             ShortHex((uint64_t)g_hook.Trampoline()).c_str());
    return true;
}

void UninstallHooks() {
    DetourSetEnabled(false);
    Sleep(120);          // 等在途回调走完，避免卸钩时踩到 trampoline
    g_hook.Uninstall();
    WxhTrampoline = 0;
    StatusBoard::Instance().SetState(WXHOOK_STATE_UNHOOKED, "uninstalled");
}

bool IsInstalled() { return g_hook.Installed(); }

void PostPayment(const std::string& amount, const std::string& raw,
                 const std::string& transNo, const std::string& sender) {
    OutEvent oe;
    oe.amount    = amount;
    oe.raw       = raw;
    oe.transNo   = transNo;
    oe.sender    = sender;
    oe.accountId = BestEffortAccountId();
    oe.atUnix    = (int64_t)time(nullptr);
    SenderPush(oe);
}

void BootstrapAsync() {
    // 注入发生在 LoadLibrary 阶段，此刻微信还没初始化完，
    // 立即扫签名会扫到未重定位的代码段 → 必须延后。
    g_bootStop.store(false);
    std::thread([] {
        g_bootAlive.store(true);
        SetThreadDescription(GetCurrentThread(), L"wxhook-bootstrap");

        for (int attempt = 0; attempt < 40; ++attempt) {
            const DWORD waitMs = (attempt < 10) ? 500 : 1500;

            // 分片睡眠，让 StopBootstrap 能及时收手（最长 100ms 响应）
            for (DWORD slept = 0; slept < waitMs; slept += 100) {
                if (g_bootStop.load()) { g_bootAlive.store(false); return; }
                Sleep(100);
            }
            if (g_bootStop.load()) { g_bootAlive.store(false); return; }

            HMODULE mod = FindWeixinModule();
            if (!mod) {
                // 必须上报，否则外部只能看到恒定的 INIT(0)，无法判断是
                // 「DLL 没装进来」还是「Weixin.dll 压根不在这个进程里」。
                // （注入到 explorer.exe 这类测试目标时就是这种情形）
                StatusBoard::Instance().SetState(
                    WXHOOK_STATE_MODULE_MISSING,
                    "Weixin.dll / WeChatWin.dll not loaded in this process");
                continue;
            }

            if (InstallHooks()) { g_bootAlive.store(false); return; }

            // 已装成功但状态不是 INSTALLED，说明是硬失败，不再重试
            auto* raw = StatusBoard::Instance().Raw();
            if (raw && (raw->state == WXHOOK_STATE_PATTERN_MISS ||
                        raw->state == WXHOOK_STATE_PROLOGUE_BAD ||
                        raw->state == WXHOOK_STATE_PATCH_FAIL)) {
                WXH_WARN("bootstrap stopped at state=%u after %d attempts",
                         raw->state, attempt + 1);
                g_bootAlive.store(false);
                return;
            }
        }
        WXH_ERR("bootstrap gave up after 40 attempts");
        g_bootAlive.store(false);
    }).detach();
}

void StopBootstrap() {
    // DllMain(DLL_PROCESS_DETACH) 里调用：让引导线程自己退出并等它走完，
    // 保证卸载期间没有线程在我们的代码段里执行。
    g_bootStop.store(true);
    for (int i = 0; i < 200 && g_bootAlive.load(); ++i) Sleep(10);   // 最多等 2s
    if (g_bootAlive.load()) {
        WXH_WARN("bootstrap thread still alive on detach; leaking it");
    }
}

}  // namespace wxh

// ── 导出函数 ─────────────────────────────────────────────────────────

extern "C" __declspec(dllexport) int __stdcall WxHookInstall(void) {
    return wxh::InstallHooks() ? 0 : 1;
}

extern "C" __declspec(dllexport) int __stdcall WxHookUninstall(void) {
    wxh::UninstallHooks();
    return 0;
}

extern "C" __declspec(dllexport) void __stdcall WxHookQueryStatus(wxhook_status* out) {
    if (!out) return;

    // 先给一个合法骨架，保证任何时刻调用都能区分「未初始化」和「读失败」。
    // 否则调用方拿到全 0 结构，magic 对不上也无从判断原因。
    std::memset(out, 0, sizeof(*out));
    out->magic       = WXHOOK_STATUS_MAGIC;
    out->abi_version = WXHOOK_ABI_VERSION;
    out->pid         = GetCurrentProcessId();
    out->started_at  = GetTickCount64();

    auto* raw = wxh::StatusBoard::Instance().Raw();
    if (raw) {
        *out = *raw;             // 状态板已映射，直接整体拷贝
        if (out->magic != WXHOOK_STATUS_MAGIC) {
            out->magic = WXHOOK_STATUS_MAGIC;   // 读取瞬间被改写的兜底
            out->abi_version = WXHOOK_ABI_VERSION;
        }
        return;
    }

    // 状态板还没映射（BootThread 尚未跑到，或 CreateFileMapping 失败）
    out->state = WXHOOK_STATE_INIT;
    _snprintf_s(out->detail, sizeof(out->detail), _TRUNCATE,
                "status board not mapped yet (boot thread pending)");
}

extern "C" __declspec(dllexport) int __stdcall WxHookPostTest(void) {
    wxh::PostPayment("0.01", "微信支付收款0.01元到账（hook selftest）", "SELFTEST", "selftest");
    return 0;
}
