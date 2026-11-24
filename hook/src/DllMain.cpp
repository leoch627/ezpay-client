#include "../include/wxhook_abi.h"
#include "Detour.h"
#include "Hook.h"
#include "Log.h"
#include "SafeRead.h"
#include "Sender.h"
#include "Status.h"

#include <windows.h>

#include <string>

namespace {

HMODULE g_self = nullptr;

// 默认投递地址。
//
// 端口用 29731：同机其他收款工具习惯占用 19088/19089 段，刻意避开。
// 必须与下列位置保持一致：
//   internal/config/config.go   listenAddr 默认值
//   hook/src/Sender.cpp         g_port 默认值
//   web/index.html              面板提示
// 改一处就要全改，否则 wxhook 推的事件网关收不到。
constexpr const char* kDefaultEndpoint = "127.0.0.1:29731/hook/payment";

// WXHOOK_ENDPOINT 环境变量可覆盖，便于调试时指向别的端口。
std::string ReadEndpoint() {
    wchar_t buf[256] = {0};
    const DWORD n = GetEnvironmentVariableW(L"WXHOOK_ENDPOINT", buf, 256);
    if (n == 0 || n >= 256) return kDefaultEndpoint;

    std::string out;
    for (DWORD i = 0; i < n && buf[i] < 0x80; ++i) out += (char)buf[i];
    return out.empty() ? kDefaultEndpoint : out;
}

std::wstring Widen(const std::string& s) {
    std::wstring w;
    w.reserve(s.size());
    for (char c : s) w += (wchar_t)(unsigned char)c;
    return w;
}

DWORD WINAPI BootThread(LPVOID) {
    wxh::LogInit(g_self);
    WXH_INFO("==== wxhook.dll loaded (pid=%lu) ====", GetCurrentProcessId());

    wxh::SafeReadInit();

    if (!wxh::StatusBoard::Instance().Open()) {
        WXH_ERR("status board open failed; continuing anyway");
    }

    // 投递端点：默认连本机网关，可用环境变量覆盖
    const std::string ep = ReadEndpoint();
    wxh::SenderStart(Widen(ep));
    WXH_INFO("endpoint = %s", ep.c_str());

    // 延迟安装：等微信把自己的模块装配完
    wxh::BootstrapAsync();
    return 0;
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE self, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            g_self = self;
            DisableThreadLibraryCalls(self);
            // 关键：DllMain 里不能做重活（加载器锁）。
            // 起一个线程立刻返回，所有初始化放到线程里。
            CloseHandle(CreateThread(nullptr, 0, BootThread, nullptr, 0, nullptr));
            break;

        case DLL_PROCESS_DETACH:
            // 进程退出时 lpReserved != nullptr，此时不要做复杂清理
            if (lpReserved == nullptr) {
                wxh::DetourSetEnabled(false);
                wxh::SenderStop();
                wxh::StatusBoard::Instance().Close();
                wxh::SafeReadShutdown();
                wxh::LogShutdown();
            }
            break;

        default:
            break;
    }
    return TRUE;
}
