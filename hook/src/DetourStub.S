// DetourStub.S —— printpb hook 的跳板
//
// 为什么用汇编写裸跳板：
//   printpb 的真实签名随微信版本漂移（而且 4.x 是 C++ protobuf 路径，参数语义不公开）。
//   如果用一个猜测的 C 函数签名去接，栈上第 5 个之后的参数会被破坏，微信直接崩。
//   所以这里只做「快照寄存器 → 交给 C 侧采样 → 原样恢复 → 尾跳 trampoline」，
//   完全不改栈、不改返回地址、不改任何参数。
//
// 栈对齐：进入时 rsp%16 == 8（retaddr 已压栈）。8 次 push = 64B（16 的倍数，仍为 8），
//         sub 0x28 = 40B，8-8 => rsp%16 == 0，满足 call 前对齐要求。
//
// 快照布局（与 Detour.cpp 的 RegSnapshot 严格一致）：
//   [rsp+0x28] r9
//   [rsp+0x30] r8
//   [rsp+0x38] rdx
//   [rsp+0x40] rcx
//   [rsp+0x48] rdi
//   [rsp+0x50] rsi
//   [rsp+0x58] rbx
//   [rsp+0x60] rbp
//   [rsp+0x68] 原始返回地址（= 调用者栈上第一个栈参数之前）

// 注意：WxhTrampoline 的**定义**在 Detour.cpp（extern "C" uint64_t WxhTrampoline = 0;）。
// 这里只做外部引用——若在此处再放一份 .quad 0 定义，链接期会 duplicate symbol。
// trampoline 每次安装时被 Hook.cpp 写一次，因此必须落在可写的 .data，不能是 .rdata。

    .text
    .align  16
    .globl  WxhDetourStub
    .def    WxhDetourStub; .scl 2; .type 32; .endef

WxhDetourStub:
    pushq   %rbp
    pushq   %rbx
    pushq   %rsi
    pushq   %rdi
    pushq   %rcx
    pushq   %rdx
    pushq   %r8
    pushq   %r9
    subq    $0x28, %rsp

    leaq    0x28(%rsp), %rcx          /* arg1: RegSnapshot*            */
    leaq    0x68(%rsp), %rdx          /* arg2: 原始 rsp（栈参数起点） */
    callq   WxhCapture

    addq    $0x28, %rsp
    popq    %r9
    popq    %r8
    popq    %rdx
    popq    %rcx
    popq    %rdi
    popq    %rsi
    popq    %rbx
    popq    %rbp

    jmpq    *WxhTrampoline(%rip)      /* 尾跳：直接进 trampoline，栈已完全复原 */
