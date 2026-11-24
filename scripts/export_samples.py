#!/usr/bin/env python3
"""
从真实 monitor.db 导出解析器回归样本。

用途：AppMsg 解析器每次改动后，用这些真实样本跑一遍，确保金额/单号仍能抽对。
输出：tests/samples.json —— 每条含 xml(明文content) + 期望值(amount_cents / out_order_no / mch_id / shop_id)

只在产生该库的同一 Windows 用户下可运行（DPAPI CurrentUser 作用域）。
"""
import base64
import ctypes
import ctypes.wintypes as wintypes
import json
import os
import re
import sqlite3
import sys

PREFIX = "enc:v1:"


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data):
    buf = ctypes.create_string_buffer(data, len(data))
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def unprotect(b64):
    raw = base64.b64decode(b64)
    bi, bo = _blob(raw), DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(bi), None, None, None, None, 0, ctypes.byref(bo))
    if not ok:
        raise OSError("CryptUnprotectData failed")
    try:
        return ctypes.string_at(bo.pbData, bo.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(bo.pbData)


def dec(v):
    if not v or not v.startswith(PREFIX):
        return v or ""
    return unprotect(v[len(PREFIX):]).decode("utf-8", "replace")


def extract(xml):
    """用与 C++ 端一致的规则抽字段，作为期望值"""
    out = {}

    # out_order_no / mch_id / shop_id / source_type
    for key in ("out_order_no", "mch_id", "shop_id", "source_type", "receipt_id"):
        m = re.search(key + r"=([A-Za-z0-9_\-]+)", xml)
        if m:
            out[key] = m.group(1)

    if "source_type" in out:
        out["source_type"] = out["source_type"].replace("E_ORDER_TRADE_FROM_TYPE_", "")

    # pub_time
    m = re.findall(r"<pub_time>(\d+)</pub_time>", xml)
    if m:
        out["pub_time"] = int(m[-1])

    # 门店
    m = re.search(r"收款门店[:：]([^\r\n]+)", xml)
    if m:
        out["store"] = m.group(1).strip()

    return out


def main():
    db = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\Leo\AppData\Local\Temp\monitor_copy.db"
    outdir = sys.argv[2] if len(sys.argv) > 2 else "samples"

    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    cur.execute("""SELECT id, source_key, content, amount_cents, callback_status
                   FROM records ORDER BY id DESC""")
    rows = cur.fetchall()

    samples = []
    seen_amounts = set()
    for r in rows:
        xml = dec(r["content"])
        if "<appmsg" not in xml:
            continue

        info = extract(xml)

        # 每种金额只留一条，避免样本重复
        amt = r["amount_cents"]
        if amt in seen_amounts and len(samples) >= 10:
            continue
        seen_amounts.add(amt)

        samples.append({
            "id": r["id"],
            "source_key": r["source_key"],
            "expected_amount_cents": amt,
            "expected_out_order_no": info.get("out_order_no", ""),
            "expected_mch_id": info.get("mch_id", ""),
            "expected_shop_id": info.get("shop_id", ""),
            "expected_source_type": info.get("source_type", ""),
            "expected_pub_time": info.get("pub_time", 0),
            "expected_store": info.get("store", ""),
            "callback_status": r["callback_status"],
            "xml": xml,
        })

        if len(samples) >= 12:
            break

    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "samples.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(samples, f, ensure_ascii=False, indent=1)

    # 顺带生成一个 C++ 头，方便把样本编译进测试
    hpath = os.path.join(outdir, "samples_generated.h")
    with open(hpath, "w", encoding="utf-8") as f:
        f.write("// 自动生成，勿手改。来源：monitor.db 真实记录\n")
        f.write("#pragma once\n\n")
        f.write("struct RealSample {\n")
        f.write("    int         id;\n")
        f.write("    const char* sourceKey;\n")
        f.write("    const char* xml;\n")
        f.write("    long long   amountCents;\n")
        f.write("    const char* outOrderNo;\n")
        f.write("    const char* mchId;\n")
        f.write("    const char* shopId;\n")
        f.write("    const char* sourceType;\n")
        f.write("    long long   pubTime;\n")
        f.write("    const char* store;\n")
        f.write("};\n\n")
        f.write("static const RealSample kRealSamples[] = {\n")
        for s in samples:
            xml = s["xml"].replace(")XYX(", ")XY\"X(")
            f.write('    { %d, "%s", R"XYX(%s)XYX", %d, "%s", "%s", "%s", "%s", %d, "%s" },\n' % (
                s["id"], s["source_key"], xml, s["expected_amount_cents"],
                s["expected_out_order_no"], s["expected_mch_id"], s["expected_shop_id"],
                s["expected_source_type"], s["expected_pub_time"], s["expected_store"]))
        f.write("};\n")
        f.write("static const int kRealSampleCount = %d;\n" % len(samples))

    con.close()
    print("导出 %d 条真实样本" % len(samples))
    print("  %s" % path)
    print("  %s" % hpath)


if __name__ == "__main__":
    main()
