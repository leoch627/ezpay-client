#include "PbWalk.h"

#include <cstring>

namespace wxh {

namespace {

constexpr uint32_t kMaxFields = 4096;

bool ReadVarint(const uint8_t*& p, const uint8_t* end, uint64_t& out) {
    out = 0;
    int shift = 0;
    while (p < end && shift < 64) {
        const uint8_t b = *p++;
        out |= (uint64_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) return true;
        shift += 7;
    }
    return false;
}

// 判断是否像可打印 UTF-8（允许中文等多字节）
bool PlausibleUtf8(const uint8_t* s, size_t n) {
    if (n < 2 || n > 8192) return false;
    size_t printable = 0, i = 0;
    while (i < n) {
        const uint8_t c = s[i];
        if (c == 0) return false;
        if (c < 0x20) {
            if (c == '\n' || c == '\r' || c == '\t') { ++printable; ++i; continue; }
            return false;
        }
        if (c < 0x80) { ++printable; ++i; continue; }
        // 多字节
        int extra = (c >= 0xF0) ? 3 : (c >= 0xE0) ? 2 : (c >= 0xC0) ? 1 : -1;
        if (extra < 0) return false;
        if (i + extra >= n) return false;
        for (int k = 1; k <= extra; ++k) {
            if ((s[i + k] & 0xC0) != 0x80) return false;
        }
        i += extra + 1;
        ++printable;
    }
    return printable >= 2;
}

void WalkLevel(const uint8_t*& p, const uint8_t* end, int depth, int maxDepth,
               uint32_t parentPath, PbWalkResult& out) {
    uint32_t seen = 0;
    while (p < end && seen < kMaxFields) {
        ++seen;

        uint64_t key = 0;
        if (!ReadVarint(p, end, key)) { out.truncated = true; return; }

        const uint32_t field = (uint32_t)(key >> 3);
        const uint32_t wire  = (uint32_t)(key & 7);
        if (field == 0 || field > 0x1FFFF) { out.truncated = true; return; }

        ++out.fields;
        const uint32_t path = ((parentPath & 0xFF) << 8) | (field & 0xFF);

        switch (wire) {
            case 0: {   // varint
                uint64_t v = 0;
                if (!ReadVarint(p, end, v)) { out.truncated = true; return; }
                out.numeric.push_back((uint8_t)(v & 0xFF));
                if (v <= 0xFFFFFFFFull) out.numeric.push_back((uint8_t)((v >> 8) & 0xFF));
                break;
            }
            case 1: {   // fixed64
                if (end - p < 8) { out.truncated = true; return; }
                p += 8;
                break;
            }
            case 2: {   // length-delimited
                uint64_t len = 0;
                if (!ReadVarint(p, end, len)) { out.truncated = true; return; }
                if (len > (uint64_t)(end - p)) { out.truncated = true; return; }

                if (len >= 2 && PlausibleUtf8(p, (size_t)len)) {
                    PbString s;
                    s.fieldPath = path;
                    s.utf8.assign(reinterpret_cast<const char*>(p), (size_t)len);
                    out.strings.push_back(std::move(s));
                } else if (depth < maxDepth && len >= 2 && len <= 65536) {
                    // 可能是嵌套子消息
                    const uint8_t* sub = p;
                    const uint8_t* subEnd = p + len;
                    const size_t before = out.strings.size();
                    WalkLevel(sub, subEnd, depth + 1, maxDepth, path, out);
                    if (out.strings.size() == before && sub != subEnd) {
                        // 不是子消息，也没抽出字符串，忽略
                    }
                }
                p += len;
                break;
            }
            case 5: {   // fixed32
                if (end - p < 4) { out.truncated = true; return; }
                p += 4;
                break;
            }
            case 3: case 4: {   // 已废弃的 group，遇到就停
                out.truncated = true;
                return;
            }
            default:
                out.truncated = true;
                return;
        }
    }
}

}  // namespace

PbWalkResult WalkProtobuf(const uint8_t* data, size_t len, int maxDepth) {
    PbWalkResult r;
    if (!data || len < 2) return r;
    const uint8_t* p = data;
    const uint8_t* end = data + len;
    WalkLevel(p, end, 0, maxDepth, 0, r);
    return r;
}

bool LooksLikePrintPb(const uint8_t* data, size_t len) {
    if (!data || len < 8 || len > 4 * 1024 * 1024) return false;

    PbWalkResult r = WalkProtobuf(data, len, 4);
    if (r.fields < 3) return false;

    for (auto& s : r.strings) {
        // 至少一条含非 ASCII（中文昵称/备注/收款文案）
        for (unsigned char c : s.utf8) {
            if (c >= 0xE0) return true;
        }
    }
    return false;
}

}  // namespace wxh
