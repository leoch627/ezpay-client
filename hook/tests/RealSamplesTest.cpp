// RealSamplesTest.cpp —— 用 12 条真实收款记录跑回归
//
// 样本由 scripts/export_samples.py 从真实 monitor.db 导出（DPAPI 解密后），
// 存在 hook/tests/samples_generated.h。每次改解析器都跑这个。
//
// 编译：
//   x86_64-w64-mingw32-g++ -std=c++20 -O1 -finput-charset=UTF-8 -fexec-charset=UTF-8 ^
//     -I../tests ../src/AppMsg.cpp RealSamplesTest.cpp -o RealSamplesTest.exe
#include "AppMsg.h"
#include "samples_generated.h"

#include <cstdio>
#include <cstring>

static int g_pass = 0;
static int g_fail = 0;

static void Expect(bool cond, const char* what, const char* got, const char* want) {
    if (cond) {
        ++g_pass;
    } else {
        ++g_fail;
        printf("    [FAIL] %s\n      got : %s\n      want: %s\n",
               what, got ? got : "", want ? want : "");
    }
}

static void ExpectLL(bool cond, const char* what, long long got, long long want) {
    if (cond) {
        ++g_pass;
    } else {
        ++g_fail;
        printf("    [FAIL] %s  got=%lld want=%lld\n", what, got, want);
    }
}

int main() {
    printf("真实样本回归：%d 条\n", kRealSampleCount);
    printf("=================================================================\n");

    for (int i = 0; i < kRealSampleCount; ++i) {
        const RealSample& s = kRealSamples[i];

        wxh::AppMsgInfo a = wxh::AmParseAppMsgXml(s.xml);

        char amtGot[32], amtWant[32];
        _snprintf_s(amtGot, sizeof(amtGot), _TRUNCATE, "%lld", (long long)a.amountCents);
        _snprintf_s(amtWant, sizeof(amtWant), _TRUNCATE, "%lld", s.amountCents);

        printf("\n[%2d] id=%-4d  %s\n", i + 1, s.id, s.sourceKey);
        printf("     金额 %-8s 单号 %-34s 来源 %-12s 门店 %s\n",
               amtGot,
               a.outOrderNo.empty() ? "(空)" : a.outOrderNo.c_str(),
               a.sourceType.empty() ? "(空)" : a.sourceType.c_str(),
               a.storeName.empty() ? "(空)" : a.storeName.c_str());

        Expect(a.isPayment, "判定为收款", a.isPayment ? "yes" : a.reason.c_str(), "yes");
        ExpectLL(a.amountCents == s.amountCents, "金额", a.amountCents, s.amountCents);
        Expect(a.outOrderNo == s.outOrderNo, "out_order_no", a.outOrderNo.c_str(), s.outOrderNo);
        Expect(a.mchId == s.mchId, "mch_id", a.mchId.c_str(), s.mchId);
        Expect(a.shopId == s.shopId, "shop_id", a.shopId.c_str(), s.shopId);
        Expect(a.sourceType == s.sourceType, "source_type", a.sourceType.c_str(), s.sourceType);
        ExpectLL(a.pubTime == s.pubTime, "pub_time", a.pubTime, s.pubTime);
        if (s.store[0]) {
            Expect(a.storeName == s.store, "门店", a.storeName.c_str(), s.store);
        }
    }

    printf("\n=================================================================\n");
    printf("通过 %d 项，失败 %d 项\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
