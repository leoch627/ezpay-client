#include "Status.h"
#include "Log.h"

#include <windows.h>

#include <cstdio>
#include <cstring>

namespace wxh {

StatusBoard& StatusBoard::Instance() {
    static StatusBoard inst;
    return inst;
}

bool StatusBoard::Open() {
    hMap_ = CreateFileMappingW(
        INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
        0, sizeof(wxhook_status), L"" WXHOOK_STATUS_NAME);
    if (!hMap_) {
        WXH_ERR("CreateFileMappingW failed: %lu", GetLastError());
        return false;
    }

    map_ = static_cast<wxhook_status*>(
        MapViewOfFile(hMap_, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(wxhook_status)));
    if (!map_) {
        WXH_ERR("MapViewOfFile failed: %lu", GetLastError());
        CloseHandle(hMap_);
        hMap_ = nullptr;
        return false;
    }

    std::memset(map_, 0, sizeof(*map_));
    map_->magic       = WXHOOK_STATUS_MAGIC;
    map_->abi_version = WXHOOK_ABI_VERSION;
    map_->pid         = GetCurrentProcessId();
    map_->started_at  = GetTickCount64();
    map_->state       = WXHOOK_STATE_INIT;
    return true;
}

void StatusBoard::Close() {
    if (map_) {
        if (map_->state != WXHOOK_STATE_UNHOOKED && map_->state != WXHOOK_STATE_INSTALLED) {
            map_->state = WXHOOK_STATE_UNHOOKED;
        }
        UnmapViewOfFile(map_);
        map_ = nullptr;
    }
    if (hMap_) {
        CloseHandle(hMap_);
        hMap_ = nullptr;
    }
}

void StatusBoard::SetState(wxhook_state st, const char* detail) {
    if (!map_) return;
    map_->state = (uint32_t)st;
    if (detail) {
        _snprintf_s(map_->detail, sizeof(map_->detail), _TRUNCATE, "%s", detail);
    }
    WXH_INFO("state -> %u (%s)", (unsigned)st, detail ? detail : "");
}

void StatusBoard::SetModule(uint64_t base, uint64_t size) {
    if (!map_) return;
    map_->module_base = base;
    map_->module_size = size;
}

void StatusBoard::SetPattern(const char* id, uint64_t target, uint64_t tramp) {
    if (!map_) return;
    map_->hook_target = target;
    map_->trampoline  = tramp;
    if (id) _snprintf_s(map_->pattern_id, sizeof(map_->pattern_id), _TRUNCATE, "%s", id);
}

void StatusBoard::SetVersion(uint32_t detected, uint32_t required) {
    if (!map_) return;
    map_->wechat_version   = detected;
    map_->required_version = required;
}

void StatusBoard::IncCallback() { if (map_) ++map_->callback_count; }
void StatusBoard::IncPayment()  { if (map_) ++map_->payment_count; }
void StatusBoard::IncPost(bool ok) { if (map_) { if (ok) ++map_->post_ok; else ++map_->post_fail; } }
void StatusBoard::IncDedup()    { if (map_) ++map_->dedup_drop; }

}  // namespace wxh
