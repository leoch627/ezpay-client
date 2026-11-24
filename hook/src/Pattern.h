// Pattern.h —— 内存特征码扫描
//
// Weixin.dll 每次小版本更新都会挪函数位置，硬编码 RVA 必挂；
// 但纯特征码扫描又容易撞上通用序言（实测 "48 8D 81 ?? ?? ?? ?? C3" 在一个
// 185 MB 的 Weixin.dll 里能撞 104 处）。
//
// 所以这里走「双重判据」：
//   1) 特征码必须是实测唯一的（见 Hook.cpp 里的注释与 scripts/extract_signatures.py）
//   2) 每条特征带一个 expectedRva，扫描到候选后要求 |命中RVA - 期望RVA| <= rvaTolerance
//      —— 跨小版本 RVA 会漂，但不会漂太远，这条能挡掉绝大多数误命中
#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace wxh {

// 特征码：'?' 通配。如 "48 8B 8? ?? ?? 00 00 E9" 匹配字节或 nibble。
struct Pattern {
    const char* id;             // 签名标识，写进状态块
    const char* text;           // "CC 0F 1F 40 00 48 89 ..."
    int32_t     hitOffset;      // 匹配点之后的额外偏移，用于跳到函数头
    uint32_t    expectedRva;    // 提取该特征时的函数 RVA（0 表示不做 RVA 校验）
    uint32_t    rvaTolerance;   // RVA 允许偏差；0 表示用默认值

    Pattern() = default;
    // 兼容旧的三字段初始化 {id, text, offset}
    Pattern(const char* i, const char* t, int32_t off)
        : id(i), text(t), hitOffset(off), expectedRva(0), rvaTolerance(0) {}
    // 四字段：{id, text, offset, rva}
    Pattern(const char* i, const char* t, int32_t off, uint32_t rva)
        : id(i), text(t), hitOffset(off), expectedRva(rva), rvaTolerance(0) {}
};

// 默认 RVA 容差。微信小版本之间函数通常漂移在几十 KB 内；
// 给到 1 MB 既能容忍合理漂移，又能挡掉"完全不相干"的误命中。
constexpr uint32_t kDefaultRvaTolerance = 1u * 1024 * 1024;

struct ScanHit {
    const Pattern* pat    = nullptr;
    uint8_t*       addr   = nullptr;
    uint32_t       rva    = 0;
    bool           rvaOk  = true;   // 是否通过了 RVA 校验
    uint32_t       rvaDist = 0;     // 与 expectedRva 的距离
};

// 把 "48 8D 8? ?? C3" 解析成 (value,mask) 序列
bool CompilePattern(const char* text, std::vector<uint8_t>& vals, std::vector<uint8_t>& masks);

// 在模块可执行节里扫描。
// 返回：第一条"通过 RVA 校验"的命中；若全都没通过，返回第一条命中的（rvaOk=false）。
ScanHit ScanModule(HMODULE mod, const std::vector<Pattern>& pats);

// 返回按节区过滤后的可执行范围
void GetCodeRanges(HMODULE mod, std::vector<std::pair<uint8_t*, size_t>>& out);

}  // namespace wxh
