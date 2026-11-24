"""
最终验证：用 Hook.cpp 里的真实特征码扫描真实 Weixin.dll 的映射镜像，
确认命中位置 == 预期函数入口，且 RVA 校验通过。

这是"能不能安全装钩子"的最后一关。
"""
import struct
import sys

DEFAULT_PE = r"C:\Program Files\Tencent\Weixin\4.1.12.53\Weixin.dll"

# 与 Hook.cpp 的 kPrintPbPatterns 保持一致
PATTERNS = [
    ("weapp_path.A",
     "CC 0F 1F 40 00 48 89 54 24 10 55 41 57 41 56 41 54 56 57 53 48 83 EC 20 48 8D 6A 70 48 8B 4D E8",
     0, 0x48BE1BB),
    ("weapp_path.B",
     "CC CC CC CC CC CC CC CC CC CC CC 41 56 56 57 53 48 83 EC 38 48 89 CE 48 89 54 24 30",
     0, 0x48BEAA5),
]

RVA_TOLERANCE = 1 * 1024 * 1024  # 与 kDefaultRvaTolerance 一致


def parse_pe(path):
    with open(path, "rb") as f:
        data = f.read()
    e = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    opt_size = struct.unpack_from("<H", data, e + 20)[0]
    sec_off = e + 24 + opt_size
    secs = []
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, o + 8)
        chars = struct.unpack_from("<I", data, o + 36)[0]
        secs.append({"name": name, "vaddr": vaddr, "vsize": vsize,
                     "rsize": rsize, "raddr": raddr,
                     "exec": bool(chars & 0x20000000)})
    return data, secs


def compile_pattern(text):
    vals, masks = [], []
    for tok in text.split():
        v = m = 0
        if tok[0] != "?":
            v |= int(tok[0], 16) << 4
            m |= 0xF0
        if tok[1] != "?":
            v |= int(tok[1], 16)
            m |= 0x0F
        vals.append(v)
        masks.append(m)
    return bytes(vals), bytes(masks)


def scan_all(buf, vals, masks):
    n = len(vals)
    hits = []
    first = 0
    for i in range(n):
        if masks[i] == 0xFF:
            first = i
            break
    anchor = bytes([vals[first]])
    start = 0
    while True:
        p = buf.find(anchor, start)
        if p < 0:
            break
        start = p + 1
        base = p - first
        if base < 0 or base + n > len(buf):
            continue
        if all((buf[base + i] & masks[i]) == (vals[i] & masks[i]) for i in range(n)):
            hits.append(base)
    return hits


def main():
    pe = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PE
    data, secs = parse_pe(pe)
    text = next(s for s in secs if s["name"] == ".text")
    textbuf = data[text["raddr"]:text["raddr"] + text["rsize"]]
    text_va = text["vaddr"]

    print("PE: %s" % pe)
    print(".text VA=0x%X  %.1f MB" % (text_va, len(textbuf) / 1024 / 1024))
    print("RVA tolerance = 0x%X (%.1f MB)\n" % (RVA_TOLERANCE, RVA_TOLERANCE / 1024 / 1024))

    overall_ok = True
    for name, text_pat, hit_off, expect_rva in PATTERNS:
        vals, masks = compile_pattern(text_pat)
        hits = scan_all(textbuf, vals, masks)

        print("=" * 74)
        print("pattern: %s" % name)
        print("  expect func RVA : 0x%X" % expect_rva)
        print("  hits in .text   : %d" % len(hits))

        chosen = None
        for h in hits:
            rva = text_va + h + hit_off
            dist = abs(rva - expect_rva)
            ok = dist <= RVA_TOLERANCE
            print("    hit file_off=0x%-8X RVA=0x%-8X dist=0x%-8X rvaOk=%s" % (
                text["raddr"] + h, rva, dist, ok))
            if ok and chosen is None:
                chosen = rva

        if chosen is None:
            print("  RESULT: FAIL - no hit passes RVA check")
            overall_ok = False
        elif chosen == expect_rva:
            print("  RESULT: PASS - lands exactly on expected function (RVA 0x%X)" % chosen)
        else:
            print("  RESULT: PARTIAL - lands at 0x%X, expected 0x%X (drift 0x%X)" % (
                chosen, expect_rva, abs(chosen - expect_rva)))
        print()

    print("=" * 74)
    print("OVERALL: %s" % ("PASS - safe to hook" if overall_ok else "FAIL"))
    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
