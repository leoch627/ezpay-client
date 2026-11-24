package main

// Windows 平台的小工具。放单独文件避免和主逻辑混在一起。

import (
	"syscall"
	"unsafe"
)

var (
	psapi              = syscall.NewLazyDLL("psapi.dll")
	procGetProcessMemoryInfo = psapi.NewProc("GetProcessMemoryInfo")
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess    = kernel32.NewProc("OpenProcess")
	procCloseHandle    = kernel32.NewProc("CloseHandle")
)

// PROCESS_MEMORY_COUNTERS 对应 Win32 同名结构体
type processMemoryCounters struct {
	Cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

// processMemMB 返回进程的工作集（MB）。拿不到返回 0。
// 面板用它把"内存最大的那个"排在前面——微信 4.x 有多个同名子进程，
// 只有内存最大、加载了 Weixin.dll 的才是主进程。
func processMemMB(pid uint32) int {
	const processQueryLimitedInformation = 0x1000
	const processVmRead = 0x0010

	h, _, _ := procOpenProcess.Call(
		uintptr(processQueryLimitedInformation|processVmRead), 0, uintptr(pid))
	if h == 0 {
		return 0
	}
	defer procCloseHandle.Call(h)

	var mc processMemoryCounters
	mc.Cb = uint32(unsafe.Sizeof(mc))
	r, _, _ := procGetProcessMemoryInfo.Call(
		h, uintptr(unsafe.Pointer(&mc)), uintptr(mc.Cb))
	if r == 0 {
		return 0
	}
	return int(mc.WorkingSetSize / (1024 * 1024))
}
