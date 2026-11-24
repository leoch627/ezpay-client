#include "../include/Inject.h"
#include "Log.h"

#include <tlhelp32.h>
#include <psapi.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace {

void SetErr(char* out, int cap, const char* msg) {
    if (!out || cap <= 0) return;
    _snprintf_s(out, cap, _TRUNCATE, "%s", msg);
}

void SetErrWin32(char* out, int cap, const char* prefix, DWORD code) {
    if (!out || cap <= 0) return;
    _snprintf_s(out, cap, _TRUNCATE, "%s (err=%lu)", prefix, code);
}

// 判断目标进程位数与当前一致（x64 客户端只注入 x64 微信）
bool IsSameBitness(HANDLE proc) {
    BOOL selfWow = FALSE, targetWow = FALSE;
    IsWow64Process(GetCurrentProcess(), &selfWow);
    IsWow64Process(proc, &targetWow);
    return selfWow == targetWow;
}

}  // namespace

int __stdcall WxInjectDLL(DWORD pid, const wchar_t* dllPath, char* errOut, int errCap) {
    if (pid == 0 || !dllPath) {
        SetErr(errOut, errCap, "invalid argument");
        return ERROR_INVALID_PARAMETER;
    }

    const DWORD myPid = GetCurrentProcessId();
    if (pid == myPid) {
        SetErr(errOut, errCap, "refuse to inject into self");
        return ERROR_INVALID_PARAMETER;
    }

    // DLL 存在性先查，避免开了进程才发现路径打不开
    DWORD attr = GetFileAttributesW(dllPath);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        SetErr(errOut, errCap, "dll not found");
        return ERROR_FILE_NOT_FOUND;
    }

    const size_t pathBytes = (wcslen(dllPath) + 1) * sizeof(wchar_t);

    HANDLE proc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!proc) {
        SetErrWin32(errOut, errCap, "OpenProcess failed (需要管理员权限)", GetLastError());
        return GetLastError();
    }

    int rc = 0;
    void* remote = nullptr;
    HANDLE thread = nullptr;

    if (!IsSameBitness(proc)) {
        SetErr(errOut, errCap, "bitness mismatch (x86 与 x64 不匹配)");
        rc = ERROR_BAD_EXE_FORMAT;
        goto cleanup;
    }

    remote = VirtualAllocEx(proc, nullptr, pathBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        rc = GetLastError();
        SetErrWin32(errOut, errCap, "VirtualAllocEx failed", rc);
        goto cleanup;
    }

    if (!WriteProcessMemory(proc, remote, dllPath, pathBytes, nullptr)) {
        rc = GetLastError();
        SetErrWin32(errOut, errCap, "WriteProcessMemory failed", rc);
        goto cleanup;
    }

    {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        auto loadLib = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(k32, "LoadLibraryW"));
        if (!loadLib) {
            rc = ERROR_PROC_NOT_FOUND;
            SetErr(errOut, errCap, "LoadLibraryW not resolved");
            goto cleanup;
        }

        thread = CreateRemoteThread(proc, nullptr, 0, loadLib, remote, 0, nullptr);
        if (!thread) {
            rc = GetLastError();
            SetErrWin32(errOut, errCap, "CreateRemoteThread failed", rc);
            goto cleanup;
        }

        const DWORD wait = WaitForSingleObject(thread, 20000);
        if (wait != WAIT_OBJECT_0) {
            rc = ERROR_TIMEOUT;
            SetErr(errOut, errCap, "LoadLibraryW 超时未返回");
            goto cleanup;
        }

        DWORD exitCode = 0;
        GetExitCodeThread(thread, &exitCode);
        // 返回 0 说明 LoadLibrary 失败
        if (exitCode == 0) {
            rc = ERROR_DLL_INIT_FAILED;
            _snprintf_s(errOut, errCap, _TRUNCATE,
                        "LoadLibraryW 返回 0（DllMain 失败或依赖缺失）");
            goto cleanup;
        }
    }

    SetErr(errOut, errCap, "ok");

cleanup:
    if (thread) CloseHandle(thread);
    if (remote) VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
    CloseHandle(proc);
    return rc;
}

int __stdcall WxFindProcessByName(const wchar_t* exeName, DWORD* pids, int cap) {
    if (!exeName || !pids || cap <= 0) return 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    int n = 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    const DWORD self = GetCurrentProcessId();
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == self || pe.th32ProcessID == 0) continue;
            if (_wcsicmp(pe.szExeFile, exeName) != 0) continue;
            if (n < cap) pids[n++] = pe.th32ProcessID;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    // 顺便过滤掉已经退出的（快照可能有残留）
    int alive = 0;
    for (int i = 0; i < n; ++i) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pids[i]);
        if (!h) continue;
        DWORD code = 0;
        if (GetExitCodeProcess(h, &code) && code == STILL_ACTIVE) {
            pids[alive++] = pids[i];
        }
        CloseHandle(h);
    }
    return alive;
}

unsigned long long __stdcall WxGetModuleBase(DWORD pid, const wchar_t* moduleName) {
    if (pid == 0 || !moduleName) return 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    unsigned long long base = 0;

    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, moduleName) == 0) {
                base = reinterpret_cast<unsigned long long>(me.modBaseAddr);
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

int __stdcall WxFindWeChatExe(wchar_t* out, int cap) {
    if (!out || cap <= 0) return 0;

    HKEY key = nullptr;
    const wchar_t* paths[] = {
        L"Software\\Tencent\\Weixin",
        L"Software\\Tencent\\WeChat",
    };

    for (const wchar_t* sub : paths) {
        if (RegOpenKeyExW(HKEY_CURRENT_USER, sub, 0, KEY_READ, &key) != ERROR_SUCCESS &&
            RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
            continue;
        }

        wchar_t buf[MAX_PATH] = {0};
        DWORD   cb  = sizeof(buf) - sizeof(wchar_t);
        DWORD   type = 0;
        if (RegQueryValueExW(key, L"InstallPath", nullptr, &type, reinterpret_cast<LPBYTE>(buf), &cb) == ERROR_SUCCESS &&
            (type == REG_SZ || type == REG_EXPAND_SZ)) {
            RegCloseKey(key);

            std::wstring dir = buf;
            if (dir.empty()) continue;

            // 有的版本存的是目录，有的是 exe 全路径
            std::wstring exe = dir;
            if (exe.size() < 4 || _wcsicmp(exe.c_str() + exe.size() - 4, L".exe") != 0) {
                if (exe.back() != L'\\') exe += L'\\';
                // 4.x 用 Weixin.exe，3.x 用 WeChat.exe
                exe += L"Weixin.exe";
                if (GetFileAttributesW(exe.c_str()) == INVALID_FILE_ATTRIBUTES) {
                    exe = dir;
                    if (exe.back() != L'\\') exe += L'\\';
                    exe += L"WeChat.exe";
                }
            }

            if (GetFileAttributesW(exe.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
            _snwprintf_s(out, cap, _TRUNCATE, L"%s", exe.c_str());
            return 1;
        }
        RegCloseKey(key);
    }
    return 0;
}
