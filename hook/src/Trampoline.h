// Trampoline.h —— x64 内联钩子（minhook 思路的极简版）
//
// 做法：
//   1. 备份目标函数前 N 字节（N = 相对跳转长度）
//   2. 把备份字节 + 一条绝对 jmp 回原函数+N 写进 trampoline
//   3. 目标头部写 jmp [rip+0] + 8 字节绝对地址 -> 我们的 handler
//   4. handler 调用 trampoline 跳板继续原逻辑
//
// 为什么不用 detour 库：这版就三种 hook 点，自己算长度比引第三方可控。
#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace wxh {

class InlineHook {
public:
    InlineHook() = default;
    ~InlineHook() { Uninstall(); }
    InlineHook(const InlineHook&) = delete;
    InlineHook& operator=(const InlineHook&) = delete;

    // 安装。target 必须是函数入口（前若干字节是可整体搬走的完整指令）。
    bool Install(uint8_t* target, uint8_t* detour, std::string* err);
    bool Uninstall();

    bool     Installed() const { return installed_; }
    uint8_t* Target()    const { return target_; }
    uint8_t* Trampoline() const { return tramp_; }

    // 校验目标头部是否是可安全搬移的指令序列；不安全就返回 false 并给原因
    static bool ValidatePrologue(uint8_t* target, size_t needBytes, std::string* why);

private:
    static bool BuildJump(uint8_t* at, uint8_t* dest, size_t slotLen);
    static size_t InstructionLen(uint8_t* p, size_t maxLen);

    uint8_t* target_    = nullptr;
    uint8_t* tramp_     = nullptr;
    uint8_t  backup_[32] = {0};
    size_t   patchLen_  = 0;
    bool     installed_ = false;
};

}  // namespace wxh
