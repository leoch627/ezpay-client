// Log.h —— 轻量日志：OutputDebugString + 文件轮转
#pragma once

#include <windows.h>

namespace wxh {

enum class LogLevel { Trace, Info, Warn, Error };

void LogInit(HMODULE self);
void LogShutdown();
void LogWrite(LogLevel lv, const char* fmt, ...);

#define WXH_INFO(...)  ::wxh::LogWrite(::wxh::LogLevel::Info,  __VA_ARGS__)
#define WXH_WARN(...)  ::wxh::LogWrite(::wxh::LogLevel::Warn,  __VA_ARGS__)
#define WXH_ERR(...)   ::wxh::LogWrite(::wxh::LogLevel::Error, __VA_ARGS__)

}  // namespace wxh
