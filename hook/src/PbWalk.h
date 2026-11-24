// PbWalk.h —— 无 schema 的 protobuf 通用遍历
//
// printpb 的结构随微信版本漂移，硬解字段号必然失效。
// 这里做的是 wire-format 层遍历：把每个 length-delimited 字段当"可能是字符串"
// 抽出来，再交给 PayParse 做语义判定。字段号只用于排序/去重，不用于解释。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace wxh {

struct PbString {
    uint32_t    fieldPath;   // 父字段号 << 8 | 本字段号，用于去重
    std::string utf8;
};

struct PbWalkResult {
    std::vector<PbString> strings;   // 可打印字符串
    std::vector<uint8_t>  numeric;   // 抽到的 varint（可能是金额/时间戳/msgid）
    size_t                fields = 0;
    bool                  truncated = false;
};

// 遍历一段 protobuf 编码。maxDepth 防止恶意嵌套爆栈。
PbWalkResult WalkProtobuf(const uint8_t* data, size_t len, int maxDepth = 6);

// 快速判定：这段 buffer 是否是「看起来像 printpb 的」protobuf
// 判据：≥3 个可解析字段，且至少含 1 条 UTF-8 中文字符串
bool LooksLikePrintPb(const uint8_t* data, size_t len);

}  // namespace wxh
