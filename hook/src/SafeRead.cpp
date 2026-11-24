#include "SafeRead.h"
#include "Log.h"

#include <windows.h>

#include <cstring>

namespace wxh {

namespace {

// 用 ReadProcessMemory 读自身进程做 probe：
// 无效地址会被内核直接拒绝并返回 FALSE，不会触发用户态 AV。
bool ProbeCopy(const void* addr, void* out, size_t len) {
    if (!addr || !out || len == 0) return false;
    SIZE_T got = 0;
    const BOOL ok = ReadProcessMemory(GetCurrentProcess(), addr, out, len, &got);
    return ok != FALSE && got == len;
}

}  // namespace

void SafeReadInit() {
    // 现在不需要 VEH；保留接口以免上层改动
    WXH_INFO("SafeRead ready (ReadProcessMemory probe mode)");
}

void SafeReadShutdown() {}

bool IsReadable(const void* addr, size_t len) {
    if (!addr || len == 0) return false;
    if (len > 64ull * 1024 * 1024) return false;

    // 先用 VirtualQuery 走一遍，把完全不可访问的区间快速否掉，
    // 避免对每个候选都做一次内核调用。
    uintptr_t cur = (uintptr_t)addr;
    const uintptr_t end = cur + len;

    while (cur < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((LPCVOID)cur, &mbi, sizeof(mbi))) return false;
        if (mbi.State != MEM_COMMIT) return false;

        const DWORD p = mbi.Protect;
        if (p & (PAGE_NOACCESS | PAGE_GUARD)) return false;

        const DWORD base = p & 0xFF;
        const bool readable = base == PAGE_READONLY || base == PAGE_READWRITE ||
                              base == PAGE_WRITECOPY || base == PAGE_EXECUTE_READ ||
                              base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
        if (!readable) return false;

        const uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (regionEnd <= cur) return false;
        cur = regionEnd;
    }

    // 再做一次真实读取，兜住 VirtualQuery 与页边界竞争的极少数情况
    char scratch[1];
    return ProbeCopy(addr, scratch, 1);
}

bool SafeRead(const void* addr, void* out, size_t len) {
    if (!addr || !out || len == 0) return false;
    if (!IsReadable(addr, len)) return false;
    return ProbeCopy(addr, out, len);
}

std::string ReadAnsiString(uintptr_t addr, size_t maxBytes) {
    std::string out;
    if (!addr || maxBytes == 0) return out;
    if (!IsReadable((void*)addr, 2)) return out;

    char buf[512];
    const size_t want = maxBytes < sizeof(buf) - 1 ? maxBytes : sizeof(buf) - 1;
    if (!SafeRead((void*)addr, buf, want)) return out;
    buf[want] = 0;

    for (size_t i = 0; i < want; ++i) {
        const unsigned char c = (unsigned char)buf[i];
        if (c == 0) { out.assign(buf, i); break; }
        if (c < 0x20 && c != '\t' && c != '\n') return std::string();
    }
    if (out.empty()) return out;

    size_t visible = 0;
    for (char c : out) if ((unsigned char)c > 0x20) ++visible;
    if (visible < 2) out.clear();
    return out;
}

}  // namespace wxh
