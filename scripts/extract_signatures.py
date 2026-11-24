"""
从真实 Weixin.dll 提取候选函数入口的特征码，并验证唯一性。

对每个候选函数：
  1. 打印入口 48 字节
  2. 取入口前 N 字节生成特征码（N 从 16 递增到 48，直到唯一）
  3. 在 113 MB 的 .text 里验证该特征码的命中次数
  4. 只有命中 = 1 的才输出为可用特征

输出可直接粘贴进 Hook.cpp 的 kPrintPbPatterns。
"""
import struct
import sys

DEFAULT_PE = r"C:\Program Files\Tencent\Weixin\4.1.12.53\Weixin.dll"

# 由 find_printpb.py 得到的候选：引用 weapp_path / <msg> 的函数
CANDIDATES = [
    ("weapp_path.A", 0x48BE1BB),
    ("weapp_path.B", 0x48BEAA5),
    ("msgtag",       0x57E0C99),
    ("mmreader.A",   0x23BE98E),
]


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
        secs.append({"name": name, "vaddr": vaddr, "rsize": rsize,
                     "raddr": raddr, "exec": bool(chars & 0x20000000)})
    return data, secs


def count_hits(buf, pat):
    """pat 是 bytes，统计精确匹配次数"""
    n = len(pat)
    hits = []
    start = 0
    while True:
        p = buf.find(pat, start)
        if p < 0:
            break
        hits.append(p)
        start = p + 1
        if len(hits) > 50:
            break
    return hits


def hexstr(b):
    return " ".join("%02X" % c for c in b)


def hexdump(b, base=0, width=16):
    out = []
    for i in range(0, len(b), width):
        chunk = b[i:i + width]
        hx = " ".join("%02X" % c for c in chunk)
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        out.append("    %08X  %-47s  %s" % (base + i, hx, asc))
    return "\n".join(out)


def main():
    pe = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PE
    data, secs = parse_pe(pe)
    text = next(s for s in secs if s["name"] == ".text")
    textbuf = data[text["raddr"]:text["raddr"] + text["rsize"]]
    text_va = text["vaddr"]

    print("file: %s" % pe)
    print(".text VA=0x%X  %.1f MB\n" % (text_va, len(textbuf) / 1024 / 1024))

    results = []

    for name, rva in CANDIDATES:
        off = rva - text_va
        if off < 0 or off + 64 > len(textbuf):
            print("### %s @ 0x%X  -- out of range\n" % (name, rva))
            continue

        entry = textbuf[off:off + 64]
        print("=" * 78)
        print("### %s   RVA 0x%X" % (name, rva))
        print("=" * 78)
        print(hexdump(entry, rva))
        print()

        # 逐步加长特征码，找到第一个"仅命中自身"的长度
        chosen = None
        chosen_len = 0
        for ln in range(12, 49, 4):
            pat = bytes(entry[:ln])
            hits = count_hits(textbuf, pat)
            # 必须只命中自己那一处
            only_self = (len(hits) == 1 and hits[0] == off)
            print("  len=%2d  hits=%2d  %s" % (
                ln, len(hits), "UNIQUE (this func)" if only_self else ""))
            if only_self:
                chosen = pat
                chosen_len = ln
                break
            if chosen is None:
                chosen = pat
                chosen_len = ln

        if chosen is not None:
            # 最终再确认一次
            hits = count_hits(textbuf, chosen)
            unique = (len(hits) == 1 and hits[0] == off)
            results.append({
                "name": name, "rva": rva, "len": chosen_len,
                "pattern": hexstr(chosen), "unique": unique,
            })
            print("\n  -> pattern (%d bytes, unique=%s):\n     %s\n" % (
                chosen_len, unique, hexstr(chosen)))

    print("=" * 78)
    print("READY-TO-PASTE PATTERNS")
    print("=" * 78)
    for r in results:
        status = "OK" if r["unique"] else "NOT UNIQUE - do not use"
        print('    { "%s", "%s", 0 },   // RVA 0x%X  [%s]' % (
            r["name"], r["pattern"], r["rva"], status))

    ok = [r for r in results if r["unique"]]
    print("\nusable: %d / %d" % (len(ok), len(results)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
