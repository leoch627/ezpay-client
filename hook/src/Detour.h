// Detour.h —— printpb 采样回调（C 侧入口，由 DetourStub.S 调用）
#pragma once

#include <cstdint>

// 与 DetourStub.S 的栈布局严格一一对应，改一个必须改另一个
struct RegSnapshot {
    uint64_t r9;
    uint64_t r8;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rbx;
    uint64_t rbp;
};

// 由汇编 stub 调用。origRsp 指向原始返回地址（栈参数在 origRsp+8 起）。
// 必须极短、无锁、不分配大内存 —— 它在微信消息线程上执行。
extern "C" void WxhCapture(const RegSnapshot* regs, uint64_t origRsp);

// DetourStub.S 里的裸跳板入口。安装钩子时把它的地址写进目标函数头部。
// 名字在 x64 MinGW 下无下划线前缀，与 .S 里的 .globl 一致。
extern "C" void WxhDetourStub(void);

// 安装时刻由 Hook.cpp 填充，stub 尾跳用。
// 定义在 Detour.cpp（可写 .data），DetourStub.S 只做外部引用。
extern "C" uint64_t WxhTrampoline;

namespace wxh {

// 采样开关：命中太频繁时可短路，避免拖慢微信
void DetourSetEnabled(bool on);

}  // namespace wxh
