// Inject.h —— 注入器 ABI（`go:linkname` 由 Go 侧调用）
#pragma once

#include <windows.h>

// 显式 dllexport：配合 -Wl,--exclude-all-symbols，
// 保证导出表里只有这 4 个名字，不会把 wxh::Log* 之类 C++ 修饰名带出去。
#define WXINJECT_API __declspec(dllexport)

#ifdef __cplusplus
extern "C" {
#endif

// 注入 DLL 到指定进程。返回 0 成功，非 0 为 Win32 错误码。
// 失败原因写入 errOut（UTF-8）。
WXINJECT_API int __stdcall WxInjectDLL(DWORD pid, const wchar_t* dllPath, char* errOut, int errCap);

// 按 exe 名枚举进程 PID（不含自身）
WXINJECT_API int __stdcall WxFindProcessByName(const wchar_t* exeName, DWORD* pids, int cap);

// 读目标进程模块基址；未加载返回 0
WXINJECT_API unsigned long long __stdcall WxGetModuleBase(DWORD pid, const wchar_t* moduleName);

// 从注册表 Software\Tencent\Weixin 的 InstallPath 找 Weixin.exe
WXINJECT_API int __stdcall WxFindWeChatExe(wchar_t* out, int cap);

#ifdef __cplusplus
}
#endif
