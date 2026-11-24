// Status.h —— 把 hook 状态发布到命名共享内存，注入器/网关可直接映射读取
// 好处：被注入进程不需要暴露任何 RPC，外部只读，零攻击面。
#pragma once

#include "../include/wxhook_abi.h"

#include <windows.h>

namespace wxh {

class StatusBoard {
public:
    static StatusBoard& Instance();

    bool Open();
    void Close();

    void SetState(wxhook_state st, const char* detail);
    void SetModule(uint64_t base, uint64_t size);
    void SetPattern(const char* id, uint64_t target, uint64_t tramp);
    void SetVersion(uint32_t detected, uint32_t required);
    void IncCallback();
    void IncPayment();
    void IncPost(bool ok);
    void IncDedup();

    wxhook_status* Raw() { return map_; }

private:
    StatusBoard() = default;
    ~StatusBoard() = default;
    StatusBoard(const StatusBoard&) = delete;
    StatusBoard& operator=(const StatusBoard&) = delete;

    HANDLE         hMap_ = nullptr;
    wxhook_status* map_  = nullptr;
};

}  // namespace wxh
