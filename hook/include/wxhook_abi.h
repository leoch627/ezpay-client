// wxhook_abi.h —— Hook DLL 与注入器/网关共享的 ABI 约定
// 这份头文件只放纯 C 结构体，双方都 include 它，避免结构体漂移。
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WXHOOK_ABI_VERSION   1
#define WXHOOK_STATUS_NAME   "Local\\WxPayHookStatus_v1"
#define WXHOOK_STATUS_MAGIC  0x57584853u   /* 'WXHS' */

/* hook 安装状态 */
typedef enum {
    WXHOOK_STATE_INIT          = 0,
    WXHOOK_STATE_MODULE_MISSING = 1,  /* Weixin.dll 未加载 */
    WXHOOK_STATE_SCANNING      = 2,
    WXHOOK_STATE_PATTERN_MISS  = 3,  /* 签名全部未命中 */
    WXHOOK_STATE_PROLOGUE_BAD  = 4,  /* 目标前导字节不安全，放弃 */
    WXHOOK_STATE_TRAMPOLINE_FAIL = 5,
    WXHOOK_STATE_PATCH_FAIL    = 6,
    WXHOOK_STATE_INSTALLED     = 7,
    WXHOOK_STATE_UNHOOKED      = 8,
    WXHOOK_STATE_VERSION_UNSUPPORTED = 9
} wxhook_state;

/* 发布到共享内存的状态块，注入器/外部进程可直接映射读取 */
typedef struct {
    uint32_t magic;              /* WXHOOK_STATUS_MAGIC */
    uint32_t abi_version;
    uint32_t state;              /* wxhook_state */
    uint32_t pid;

    uint64_t module_base;        /* Weixin.dll 基址 */
    uint64_t module_size;
    uint64_t hook_target;        /* 命中函数地址（相对模块的 RVA 见下） */
    uint64_t hook_rva;           /* 若静态解析，填 RVA */
    uint64_t trampoline;

    uint32_t wechat_version;     /* 编码版本，见 VersionPack() */
    uint32_t required_version;

    uint64_t callback_count;     /* 命中 printpb 的总次数 */
    uint64_t payment_count;      /* 判定为收款的事件数 */
    uint64_t post_ok;            /* 投递成功次数 */
    uint64_t post_fail;
    uint64_t dedup_drop;         /* 去重丢弃次数 */

    uint64_t last_hit_at;        /* 最近一次命中（GetTickCount64） */
    uint64_t started_at;

    char     pattern_id[64];     /* 命中的签名标识 */
    char     detail[256];        /* 人类可读说明 */
} wxhook_status;

/* 版本编码：4.1.48.13 -> 0x0401300D，便于直接比较 */
static inline uint32_t WxPackVersion(int major, int minor, int build, int rev) {
    return ((uint32_t)(major & 0xFF) << 24) |
           ((uint32_t)(minor & 0xFF) << 16) |
           ((uint32_t)(build & 0xFF) << 8)  |
           ((uint32_t)(rev   & 0xFF));
}

/* DLL 导出的两个控制函数，注入器可选调用 */
typedef int  (__stdcall *PFN_WxHookInstall)(void);
typedef int  (__stdcall *PFN_WxHookUninstall)(void);
typedef void (__stdcall *PFN_WxHookQueryStatus)(wxhook_status* out);

#ifdef __cplusplus
}
#endif
