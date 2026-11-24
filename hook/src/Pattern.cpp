#include "Pattern.h"

#include <cstring>

namespace wxh {

namespace {

inline int HexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

inline bool IsExecutable(DWORD prot) {
    return (prot & 0xF0) == PAGE_EXECUTE_READ ||
           (prot & 0xF0) == PAGE_EXECUTE_READWRITE ||
           (prot & 0xF0) == PAGE_EXECUTE_WRITECOPY ||
           (prot & 0xF0) == PAGE_EXECUTE;
}

}  // namespace

bool CompilePattern(const char* text, std::vector<uint8_t>& vals, std::vector<uint8_t>& masks) {
    vals.clear();
    masks.clear();
    if (!text) return false;

    const char* p = text;
    while (*p) {
        while (*p == ' ') ++p;
        if (!*p) break;

        // 单字节（允许 nibble 通配，如 8?）
        char hi = *p++;
        if (!*p) return false;
        char lo = *p++;
        while (*p == ' ') ++p;

        uint8_t v = 0, m = 0;
        int h = HexVal(hi);
        int l = HexVal(lo);
        if (hi == '?') { m &= 0x0F; } else { if (h < 0) return false; v |= (uint8_t)(h << 4); m |= 0xF0; }
        if (lo == '?') { m &= 0xF0; } else { if (l < 0) return false; v |= (uint8_t)l; m |= 0x0F; }

        // 两个都是 '?' 视为整字节通配
        if (hi == '?' && lo == '?') { v = 0; m = 0; }

        vals.push_back(v);
        masks.push_back(m);
    }
    return !vals.empty();
}

void GetCodeRanges(HMODULE mod, std::vector<std::pair<uint8_t*, size_t>>& out) {
    out.clear();
    if (!mod) return;

    auto* base = reinterpret_cast<uint8_t*>(mod);
    auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        const DWORD ch = sec->Characteristics;
        if (!(ch & IMAGE_SCN_MEM_EXECUTE)) continue;

        uint8_t* start = base + sec->VirtualAddress;
        size_t   size  = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (!size) continue;

        // 只保留真正可执行的部分（有的包会把 .rdata 标成 EXECUTE 但没内容）
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(start, &mbi, sizeof(mbi))) continue;
        if (!IsExecutable(mbi.Protect)) continue;

        out.emplace_back(start, size);
    }
}

ScanHit ScanModule(HMODULE mod, const std::vector<Pattern>& pats) {
    ScanHit miss{};
    if (!mod || pats.empty()) return miss;

    std::vector<std::pair<uint8_t*, size_t>> ranges;
    GetCodeRanges(mod, ranges);
    if (ranges.empty()) return miss;

    // 预编译全部特征
    struct CP { const Pattern* pat; std::vector<uint8_t> v, m; };
    std::vector<CP> compiled;
    compiled.reserve(pats.size());
    for (auto& p : pats) {
        CP c;
        c.pat = &p;
        if (!CompilePattern(p.text, c.v, c.m)) continue;
        compiled.push_back(std::move(c));
    }
    if (compiled.empty()) return miss;

    // 双重判据：先收集所有命中，优先返回"通过 RVA 校验"的那一条；
    // 全都没通过时返回第一条并标记 rvaOk=false，交给上层决定是否放弃。
    ScanHit firstAny{};
    bool haveAny = false;

    for (auto& [start, size] : ranges) {
        if (size < 16) continue;

        uint8_t* end = start + size;
        for (uint8_t* cur = start; cur + 16 < end; ++cur) {
            for (auto& c : compiled) {
                const size_t n = c.v.size();
                if (cur + n > end) continue;

                bool ok = true;
                for (size_t i = 0; i < n; ++i) {
                    if ((cur[i] & c.m[i]) != (c.v[i] & c.m[i])) { ok = false; break; }
                }
                if (!ok) continue;

                ScanHit hit;
                hit.pat  = c.pat;
                hit.addr = cur + c.pat->hitOffset;
                hit.rva  = (uint32_t)((uintptr_t)hit.addr - (uintptr_t)mod);

                if (c.pat->expectedRva != 0) {
                    const uint32_t tol = c.pat->rvaTolerance ? c.pat->rvaTolerance
                                                             : kDefaultRvaTolerance;
                    const uint32_t d = (hit.rva > c.pat->expectedRva)
                                           ? (hit.rva - c.pat->expectedRva)
                                           : (c.pat->expectedRva - hit.rva);
                    hit.rvaDist = d;
                    hit.rvaOk   = (d <= tol);
                } else {
                    hit.rvaOk = true;
                }

                if (hit.rvaOk) return hit;
                if (!haveAny) { firstAny = hit; haveAny = true; }
            }
        }
    }

    if (haveAny) return firstAny;
    return miss;
}

}  // namespace wxh
