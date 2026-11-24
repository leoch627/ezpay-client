#include "Trampoline.h"
#include "Log.h"

#include <cstring>

namespace wxh {

namespace {

// ── ModRM/SIB 长度计算 ────────────────────────────────────────────────
// 返回 modrm(含 sib/disp) 的总字节数；0 表示不可解析
size_t ModRmLen(const uint8_t* p, size_t max, bool addr32, size_t* immNeeded) {
    if (max < 1) return 0;
    const uint8_t modrm = p[0];
    const uint8_t mod   = modrm >> 6;
    const uint8_t rm    = modrm & 7;

    size_t n = 1;

    if (mod != 3) {
        if (rm == 4) {
            // SIB
            if (max < n + 1) return 0;
            const uint8_t sib  = p[n];
            const uint8_t base = sib & 7;
            n += 1;
            if (mod == 0 && base == 5) n += 4;
        }
        if (mod == 0) {
            if (rm == 5) n += 4;             // RIP-relative
        } else if (mod == 1) {
            n += 1;
        } else if (mod == 2) {
            n += 4;
        }
    }
    (void)addr32;
    if (immNeeded) *immNeeded = 0;
    return n;
}

bool HasModRm(uint8_t op) {
    // 覆盖 x64 函数前导里实际会出现的带 ModRM 主操作码
    if (op <= 0x3F) {
        const uint8_t lo = op & 7;
        if (op >= 0x00 && op <= 0x3B && (lo <= 3)) return true;
    }
    if (op == 0x62 || op == 0x63) return true;
    if (op == 0x69 || op == 0x6B) return true;
    if (op >= 0x80 && op <= 0x8F) return true;
    if (op == 0xC0 || op == 0xC1 || op == 0xC6 || op == 0xC7) return true;
    if (op >= 0xD0 && op <= 0xD3) return true;
    if (op == 0xF6 || op == 0xF7) return true;
    if (op == 0xFE || op == 0xFF) return true;
    return false;
}

}  // namespace

size_t InlineHook::InstructionLen(uint8_t* code, size_t max) {
    size_t i = 0;
    bool opsize16 = false;

    // 前缀
    for (; i < max && i < 8; ) {
        const uint8_t b = code[i];
        if (b == 0x66) { opsize16 = true; ++i; continue; }
        if (b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3) { ++i; continue; }
        if (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) { ++i; continue; }
        break;
    }
    if (i >= max) return 0;

    bool rexW = false;
    if ((code[i] & 0xF0) == 0x40) {
        rexW = (code[i] & 0x08) != 0;
        ++i;
    }
    if (i >= max) return 0;

    const uint8_t op = code[i++];

    // 单字节、无操作数
    if (op == 0x90 || op == 0xC3 || op == 0xCC || op == 0xC9 || op == 0xCB ||
        (op >= 0x50 && op <= 0x5F) || (op >= 0x91 && op <= 0x97)) {
        return i;
    }

    // push/pop r8-r15 已由 0x50-0x5F 覆盖，REX 前缀情况同样计入

    // mov r, imm
    if (op >= 0xB0 && op <= 0xB7) return i + 1;
    if (op >= 0xB8 && op <= 0xBF) return i + (rexW ? 8 : (opsize16 ? 2 : 4));

    // mov r/m, imm 组
    if (op == 0xC6) {
        const size_t ml = ModRmLen(code + i, max - i, false, nullptr);
        return ml ? i + ml + 1 : 0;
    }
    if (op == 0xC7) {
        const size_t ml = ModRmLen(code + i, max - i, false, nullptr);
        return ml ? i + ml + (rexW ? 4 : (opsize16 ? 2 : 4)) : 0;
    }

    // 短跳 / 条件跳转 rel8
    if (op == 0xEB || (op >= 0x70 && op <= 0x7F)) return i + 1;
    // jmp rel32 / call rel32
    if (op == 0xE9 || op == 0xE8) return i + 4;

    // 0F 双字节
    if (op == 0x0F) {
        if (i >= max) return 0;
        const uint8_t op2 = code[i++];
        if (op2 >= 0x80 && op2 <= 0x8F) return i + 4;          // jcc rel32
        if (op2 == 0x05 || op2 == 0x07 || op2 == 0x0B || op2 == 0x31 ||
            op2 == 0x1F || op2 == 0x28 || op2 == 0x29 || op2 == 0x57 ||
            op2 == 0x10 || op2 == 0x11 || op2 == 0x6E || op2 == 0x7E ||
            op2 == 0xAF || op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF) {
            const size_t ml = ModRmLen(code + i, max - i, false, nullptr);
            return ml ? i + ml : 0;
        }
        return 0;   // 未知 0F 扩展，拒绝
    }

    // 带 ModRM 且可能跟 imm 的算逻指令组
    if (HasModRm(op)) {
        const size_t ml = ModRmLen(code + i, max - i, false, nullptr);
        if (!ml) return 0;
        size_t imm = 0;

        if (op == 0x80 || op == 0x83 || op == 0xC0 || op == 0xC1 || op == 0x6B) {
            imm = 1;
        } else if (op == 0x81 || op == 0x69) {
            imm = opsize16 ? 2 : 4;
        } else if (op == 0xF6) {
            const uint8_t reg = (code[i] >> 3) & 7;
            if (reg == 0 || reg == 1) imm = 1;
        } else if (op == 0xF7) {
            const uint8_t reg = (code[i] >> 3) & 7;
            if (reg == 0 || reg == 1) imm = rexW ? 4 : (opsize16 ? 2 : 4);
        }
        return i + ml + imm;
    }

    return 0;   // 未覆盖的操作码 → 上层按“不安全”处理
}

bool InlineHook::ValidatePrologue(uint8_t* target, size_t needBytes, std::string* why) {
    if (!target) { if (why) *why = "null target"; return false; }
    if (IsBadReadPtr(target, needBytes + 16)) { if (why) *why = "target unreadable"; return false; }

    size_t total = 0;
    int    guard = 0;
    while (total < needBytes) {
        if (++guard > 16) { if (why) *why = "prologue too long"; return false; }
        const size_t n = InstructionLen(target + total, 32);
        if (!n) {
            if (why) *why = "unknown opcode in prologue";
            return false;
        }
        total += n;
    }
    return true;
}

bool InlineHook::BuildJump(uint8_t* at, uint8_t* dest, size_t slotLen) {
    // FF 25 00000000 <abs64>  = 14 字节绝对跳转
    if (slotLen < 14) return false;
    at[0] = 0xFF;
    at[1] = 0x25;
    *reinterpret_cast<uint32_t*>(at + 2) = 0;
    *reinterpret_cast<uint64_t*>(at + 6) = reinterpret_cast<uint64_t>(dest);
    if (slotLen > 14) {
        std::memset(at + 14, 0x90, slotLen - 14);
    }
    return true;
}

bool InlineHook::Install(uint8_t* target, uint8_t* detour, std::string* err) {
    if (installed_) { if (err) *err = "already installed"; return false; }
    if (!target || !detour) { if (err) *err = "null arg"; return false; }

    // 1) 计算需要搬移的字节数（至少 14）
    size_t need = 0;
    int    guard = 0;
    while (need < 14) {
        if (++guard > 16) { if (err) *err = "prologue too long"; return false; }
        const size_t n = InstructionLen(target + need, 32);
        if (!n) { if (err) *err = "unsafe prologue (unknown opcode)"; return false; }
        need += n;
    }
    if (need > sizeof(backup_)) { if (err) *err = "prologue larger than backup"; return false; }

    // 2) 分配 trampoline（可执行）
    tramp_ = static_cast<uint8_t*>(VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!tramp_) { if (err) *err = "VirtualAlloc trampoline failed"; return false; }

    // 3) 备份原字节 + 构造 trampoline = 原指令 + jmp 回 target+need
    std::memcpy(backup_, target, need);
    std::memcpy(tramp_, target, need);
    if (!BuildJump(tramp_ + need, target + need, 14)) {
        VirtualFree(tramp_, 0, MEM_RELEASE);
        tramp_ = nullptr;
        if (err) *err = "build trampoline jump failed";
        return false;
    }

    // 4) 改写目标头
    DWORD old = 0;
    if (!VirtualProtect(target, need, PAGE_EXECUTE_READWRITE, &old)) {
        VirtualFree(tramp_, 0, MEM_RELEASE);
        tramp_ = nullptr;
        if (err) *err = "VirtualProtect(target) failed";
        return false;
    }
    BuildJump(target, detour, need);
    FlushInstructionCache(GetCurrentProcess(), target, need);
    VirtualProtect(target, need, old, &old);

    target_    = target;
    patchLen_  = need;
    installed_ = true;
    WXH_INFO("hook installed: target=0x%p detour=0x%p tramp=0x%p patch=%zuB",
             (void*)target, (void*)detour, (void*)tramp_, need);
    return true;
}

bool InlineHook::Uninstall() {
    if (!installed_ || !target_) return true;

    DWORD old = 0;
    if (VirtualProtect(target_, patchLen_, PAGE_EXECUTE_READWRITE, &old)) {
        std::memcpy(target_, backup_, patchLen_);
        FlushInstructionCache(GetCurrentProcess(), target_, patchLen_);
        VirtualProtect(target_, patchLen_, old, &old);
    }
    if (tramp_) {
        VirtualFree(tramp_, 0, MEM_RELEASE);
        tramp_ = nullptr;
    }
    installed_ = false;
    WXH_INFO("hook uninstalled: target=0x%p", (void*)target_);
    return true;
}

}  // namespace wxh
