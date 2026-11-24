// Sender.h —— 投递队列：把事件从微信线程搬到独立线程，再 POST 给网关
//
// 为什么必须异步：
//   printpb 是在微信的消息处理链上被调用的。在这里做 HTTP 会直接卡住微信 UI，
//   尤其网关不在线时（超时 5s）会造成消息堆积、界面假死。
#pragma once

#include <string>

namespace wxh {

struct OutEvent {
    std::string amount;
    std::string raw;
    std::string transNo;
    std::string sender;
    std::string accountId;
    // appmsg XML 专用，网关可选用
    std::string mchId;
    std::string shopId;
    std::string sourceType;
    int64_t     atUnix = 0;
};

void SenderStart(const std::wstring& endpoint);
void SenderStop();
void SenderPush(const OutEvent& ev);

}  // namespace wxh
