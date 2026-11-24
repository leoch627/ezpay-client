// SafeRead.h —— 跨线程安全读目标进程内存
//
// 目标内存可能是野指针、已释放页、或跨越保护区边界。
// 直接解引用会抛 AV，在微信线程上抛就是崩溃。
//
// 这里不用 SEH（clang/MinGW 对 __try/__except 支持不完整），
// 改用 ReadProcessMemory 读自身进程：内核负责处理无效地址，失败返回 FALSE，
// 不会在本线程抛出任何异常。这是 Windows 上最稳的 probe 方式。
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace wxh {

void SafeReadInit();
void SafeReadShutdown();

// 读一块内存；越界/不可读都返回 false，绝不抛异常
bool SafeRead(const void* addr, void* out, size_t len);

// 判断 [addr, addr+len) 是否全部可读（先做 VirtualQuery 快筛，再做 probe）
bool IsReadable(const void* addr, size_t len);

// 把指针当 C 字符串读（微信内部字符串多为 std::wstring / wchar_t* / char*）
std::string ReadAnsiString(uintptr_t addr, size_t maxBytes = 256);

}  // namespace wxh
