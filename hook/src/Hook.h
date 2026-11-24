// Hook.h —— 主控：找模块、扫签名、装钩子、投递事件
#pragma once

#include "../include/wxhook_abi.h"

#include <windows.h>

#include <string>
#include <vector>

namespace wxh {

// 导出的控制函数（注入器/网关可远程调用，也可由 DllMain 自动触发）
extern "C" {
__declspec(dllexport) int  __stdcall WxHookInstall(void);
__declspec(dllexport) int  __stdcall WxHookUninstall(void);
__declspec(dllexport) void __stdcall WxHookQueryStatus(wxhook_status* out);
}

// DllMain 里启动的引导流程
void BootstrapAsync();

// DLL 卸载前停掉引导线程（等它真正退出，避免卸载后野指令）
void StopBootstrap();

// 从任意线程触发一次安装尝试（幂等）
bool InstallHooks();
void UninstallHooks();

bool IsInstalled();

// 把一条收款事件投递到本机网关（后台队列，不阻塞微信线程）
void PostPayment(const std::string& amount, const std::string& raw,
                 const std::string& transNo, const std::string& sender);

// 读当前登录 wxid（尽力而为，失败返回空）
std::string BestEffortAccountId();

// 读微信版本（4 字节编码），失败返回 0
uint32_t DetectWeChatVersion();

}  // namespace wxh
