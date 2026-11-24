// AppMsgTest.cpp —— 用真实样本验证 AppMsg 解析器
// 编译：x86_64-w64-mingw32-g++ -std=c++20 -O1 AppMsg.cpp AppMsgTest.cpp -o AppMsgTest.exe
#include "AppMsg.h"

#include <cstdio>
#include <cstring>
#include <string>

using namespace wxh;

// 真实样本 1：经营码收款（SHOP_QRCODE）—— 来自 monitor.db id=276
static const char* kShopQr = R"(<?xml version="1.0"?>
<msg>
	<appmsg appid="" sdkver="0">
		<title><![CDATA[[店员消息]收款到账134.99元]]></title>
		<des><![CDATA[收款金额￥134.99
收款门店:leochang
收款说明:经营收款事项
说明:已存入店长leochang(**店)的经营账户]]></des>
		<action />
		<type>5</type>
		<mmreader>
			<category type="0" count="1">
				<topnew>
					<item>
						<title><![CDATA[[店员消息]收款到账134.99元]]></title>
						<pub_time>1794881757</pub_time>
						<digest><![CDATA[收款金额￥134.99]]></digest>
						<weapp_path><![CDATA[pages/mini-receipt/order-detail/order-detail.html?account_type=E_MINI_RECEIPT_EACCOUNT_TYPE_SJT&source_type=E_ORDER_TRADE_FROM_TYPE_SHOP_QRCODE&shop_id=43030953&out_order_no=10259366458017948817520115990500&operator_role=E_MINI_RECEIPT_OPERATOR_ROLE_ASSISTANT&mch_id=805242195&from=mini_receipt_assistant_msg_detail]]></weapp_path>
					</item>
				</topnew>
				<publisher><username><![CDATA[gh_f0a92aa7146c]]></username><nickname><![CDATA[微信收款助手]]></nickname></publisher>
				<template_header><title><![CDATA[经营码收款到账通知]]></title><pub_time>1794881757</pub_time></template_header>
			</category>
		</mmreader>
	</appmsg>
</msg>)";

// 真实样本 2：链接收款（MCH_QRCODE）—— 来自 monitor.db id=277
static const char* kMchQr = R"(<?xml version="1.0"?>
<msg>
	<appmsg appid="" sdkver="0">
		<title><![CDATA[[店员消息]收款到账130.00元]]></title>
		<des><![CDATA[收款金额￥130.00
收款门店:leochang
收款说明:收款
说明:已存入店长leochang(**店)的经营账户]]></des>
		<type>5</type>
		<mmreader>
			<category><topnew><item>
				<title><![CDATA[[店员消息]收款到账130.00元]]></title>
				<pub_time>1794907986</pub_time>
				<weapp_path><![CDATA[pages/mini-receipt/order-detail/order-detail.html?account_type=E_MINI_RECEIPT_EACCOUNT_TYPE_SJT&source_type=E_ORDER_TRADE_FROM_TYPE_MCH_QRCODE&shop_id=43030953&out_order_no=TON3UZ-00BT0SR-0DBF4UR-KP94HZ8I&operator_role=E_MINI_RECEIPT_OPERATOR_ROLE_ASSISTANT&mch_id=805242195&from=mini_receipt_assistant_msg_detail]]></weapp_path>
			</item></topnew></category>
			<template_header><title><![CDATA[链接收款到账通知]]></title></template_header>
		</mmreader>
	</appmsg>
</msg>)";

// 负样本 1：退款通知，必须被过滤
static const char* kRefund = R"(<?xml version="1.0"?>
<msg><appmsg><title><![CDATA[收款退款到账通知]]></title>
<des><![CDATA[已退款￥50.00]]></des>
<mmreader><category><topnew><item>
<pub_time>1794907986</pub_time>
<weapp_path><![CDATA[x?out_order_no=ABC123456789012345&mch_id=805242195]]></weapp_path>
</item></topnew></category></mmreader></appmsg></msg>)";

// 负样本 2：普通聊天消息
static const char* kChat = R"(<?xml version="1.0"?>
<msg><appmsg><title><![CDATA[你好]]></title><type>1</type></appmsg></msg>)";

static int g_fail = 0;

static void Check(bool cond, const char* what) {
    printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond) ++g_fail;
}

int main() {
    printf("=== 样本 1：经营码收款（SHOP_QRCODE）===\n");
    {
        AppMsgInfo a = wxh::AmParseAppMsgXml(kShopQr);
        printf("  isPayment=%d amount=%lld title=%s\n", (int)a.isPayment,
               (long long)a.amountCents, a.title.c_str());
        printf("  outOrderNo=%s mch=%s shop=%s src=%s store=%s pub=%lld\n",
               a.outOrderNo.c_str(), a.mchId.c_str(), a.shopId.c_str(),
               a.sourceType.c_str(), a.storeName.c_str(), (long long)a.pubTime);
        if (!a.isPayment) printf("  reason=%s\n", a.reason.c_str());
        Check(a.isPayment, "判定为收款");
        Check(a.amountCents == 13499, "金额 134.99 -> 13499 分");
        Check(a.outOrderNo == "10259366458017948817520115990500", "out_order_no 抽取正确");
        Check(a.mchId == "805242195", "mch_id 抽取正确");
        Check(a.shopId == "43030953", "shop_id 抽取正确");
        Check(a.sourceType == "SHOP_QRCODE", "source_type 归一化为 SHOP_QRCODE");
        Check(a.storeName == "leochang", "门店名抽取正确");
        Check(a.pubTime == 1794881757, "pub_time 抽取正确");
    }

    printf("\n=== 样本 2：链接收款（MCH_QRCODE）===\n");
    {
        AppMsgInfo a = wxh::AmParseAppMsgXml(kMchQr);
        printf("  isPayment=%d amount=%lld outOrderNo=%s src=%s\n", (int)a.isPayment,
               (long long)a.amountCents, a.outOrderNo.c_str(), a.sourceType.c_str());
        Check(a.isPayment, "判定为收款");
        Check(a.amountCents == 13000, "金额 130.00 -> 13000 分（保留两位小数）");
        Check(a.outOrderNo == "TON3UZ-00BT0SR-0DBF4UR-KP94HZ8I", "分段单号抽取正确");
        Check(a.sourceType == "MCH_QRCODE", "source_type 归一化为 MCH_QRCODE");
    }

    printf("\n=== 负样本 1：退款 ===\n");
    {
        AppMsgInfo a = wxh::AmParseAppMsgXml(kRefund);
        printf("  isPayment=%d isRefund=%d reason=%s\n", (int)a.isPayment,
               (int)a.isRefund, a.reason.c_str());
        Check(!a.isPayment, "退款被拒绝");
        Check(a.isRefund, "标记为退款");
    }

    printf("\n=== 负样本 2：普通聊天 ===\n");
    {
        AppMsgInfo a = wxh::AmParseAppMsgXml(kChat);
        printf("  isPayment=%d reason=%s\n", (int)a.isPayment, a.reason.c_str());
        Check(!a.isPayment, "普通消息被拒绝");
    }

    printf("\n=== 边界：AmLooksLikeAppMsgXml ===\n");
    {
        Check(wxh::AmLooksLikeAppMsgXml((const uint8_t*)kShopQr, strlen(kShopQr)), "识别 <%xml 开头");
        Check(!wxh::AmLooksLikeAppMsgXml((const uint8_t*)"hello world!!!", 14), "普通文本拒绝");
        Check(!wxh::AmLooksLikeAppMsgXml(nullptr, 0), "null 拒绝");
    }

    printf("\n=== 边界：金额抽取各种写法 ===\n");
    {
        struct { const char* t; int64_t want; } cases[] = {
            { "收款到账130.00元", 13000 },
            { "收款金额￥134.99", 13499 },
            { "收款金额: 12.34", 1234 },
            { "到账 ¥ 0.01", 1 },
            { "收款到账1000元", 100000 },
            { "没有任何金额", 0 },
            { "转账 500 元", 0 },
        };
        for (auto& c : cases) {
            int64_t got = wxh::AmExtractAmountCents(c.t);
            printf("  %-28s -> %lld (want %lld)\n", c.t, (long long)got, (long long)c.want);
            if (got != c.want) { ++g_fail; printf("    ^^^ FAIL\n"); }
        }
    }

    printf("\n================================\n");
    printf("%s  (failures=%d)\n", g_fail == 0 ? "ALL PASS" : "SOME FAILED", g_fail);
    return g_fail == 0 ? 0 : 1;
}
