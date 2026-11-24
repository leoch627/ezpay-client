// Log.cpp —— 轻量日志：OutputDebugString + 文件轮转
//
// 线程安全约定（踩过的坑，别改回去）：
//   g_mu 是普通 std::mutex（非递归）。任何已经持有 g_mu 的代码路径
//   都只能调用 WriteLocked* 系列，绝不能回头调 LogWrite ——
//   否则同一线程二次加锁，当场自死锁。这个死锁曾经让 BootThread
//   卡在 LogInit 里，导致状态板从未打开、钩子从未安装。

#include "Log.h"

#include <cstdarg>
#include <cstdio>
#include <mutex>

namespace wxh {
namespace {

std::mutex  g_mu;
FILE*       g_file        = nullptr;
LogLevel    g_level       = LogLevel::Info;
bool        g_inited      = false;
wchar_t     g_logPath[MAX_PATH] = {0};

const char* LevelTag(LogLevel lv) {
    switch (lv) {
        case LogLevel::Trace: return "TRC";
        case LogLevel::Info:  return "INF";
        case LogLevel::Warn:  return "WRN";
        case LogLevel::Error: return "ERR";
    }
    return "???";
}

// 前置声明：下面两个 WriteLocked 互为重载
void WriteLockedV(LogLevel lv, const char* fmt, va_list ap);

// 无锁实现体。调用者必须已持有 g_mu。
void WriteLockedV(LogLevel lv, const char* fmt, va_list ap) {
    if (lv < g_level) return;

    char body[2048];
    _vsnprintf_s(body, sizeof(body), _TRUNCATE, fmt, ap);

    SYSTEMTIME st;
    GetLocalTime(&st);
    char line[2304];
    _snprintf_s(line, sizeof(line), _TRUNCATE,
                "[%02u:%02u:%02u.%03u][%s][tid=%lu] %s\n",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                LevelTag(lv), GetCurrentThreadId(), body);

    OutputDebugStringA(line);

    if (g_file) {
        fputs(line, g_file);
        fflush(g_file);
    }
}

// 同上的可变参数入口，供持锁的内部调用方使用。
void WriteLocked(LogLevel lv, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    WriteLockedV(lv, fmt, ap);
    va_end(ap);
}

}  // namespace

void LogInit(HMODULE self) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_inited) return;
    g_inited = true;

    // 日志落在 Weixin.exe 同目录的 logs/ 下，避免写系统盘
    wchar_t exePath[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    wchar_t* slash = wcsrchr(exePath, L'\\');
    if (slash) *(slash + 1) = 0;

    // 注意：宽字符格式化里 %s 是「窄字符串」，传 wchar_t* 必须用 %ls。
    // 早先写成 %s 会让 _snwprintf_s 把宽指针当 char* 解，拼出乱码路径。
    wchar_t dir[MAX_PATH];
    _snwprintf_s(dir, MAX_PATH, _TRUNCATE, L"%lslogs", exePath);
    CreateDirectoryW(dir, nullptr);

    _snwprintf_s(g_logPath, MAX_PATH, _TRUNCATE, L"%lswxpay_hook.log", dir);
    // 追加模式；超过 8MB 时截断重来
    WIN32_FILE_ATTRIBUTE_DATA fad = {};
    if (GetFileAttributesExW(g_logPath, GetFileExInfoStandard, &fad)) {
        ULONGLONG sz = ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
        if (sz > 8ull * 1024 * 1024) DeleteFileW(g_logPath);
    }
    _wfopen_s(&g_file, g_logPath, L"ab");

    // 已持锁 → 走 WriteLocked，不能调 LogWrite
    WriteLocked(LogLevel::Info,
                "==== hook dll attached (self=0x%p, pid=%lu) log=%ls ====",
                (void*)self, GetCurrentProcessId(), g_logPath);
}

void LogShutdown() {
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_file) { fclose(g_file); g_file = nullptr; }
    g_inited = false;
}

void LogWrite(LogLevel lv, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    {
        std::lock_guard<std::mutex> lk(g_mu);
        WriteLockedV(lv, fmt, ap);
    }
    va_end(ap);
}

}  // namespace wxh
