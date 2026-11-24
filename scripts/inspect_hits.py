"""
提取真实 Weixin.dll 里特征码命中点附近的字节与反汇编线索，
用于判断这两个唯一命中点到底是不是 printpb。

输出：
  1) 命中点在文件中的偏移 + RVA
  2) 前后 64 字节 hex
  3) 附近是否出现 printpb 相关字符串引用（.rdata 里的 "printpb" / "<msg" / "appmsg"）
"""
import struct
import sys

DEFAULT_PE = r"C:\Program Files\Tencent\Weixin\4.1.12.53\Weixin.dll"

TARGETS = [
    ("printpb.mov-esi-ecx-stor",      "48 89 CE 89 11 45 0F 57 C0"),
    ("printpb.call-jmp-thunk",        "BA 01 00 00 00 F0 0F C1 15 ?? ?? ?? ?? E9"),
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
        secs.append({"name": name, "vsize": vsize, "vaddr": vaddr,
                     "rsize": rsize, "raddr": raddr, "exec": bool(chars & 0x20000000)})
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


def find_all(buf, vals, masks, limit=20):
    n = len(vals)
    hits = []
    first = 0
    for i in range(n):
        if masks[i] == 0xFF:
            first = i
            break
    anchor = bytes([vals[first]])
    start = 0
    while len(hits) < limit:
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


def hexdump(b, base=0, width=16):
    out = []
    for i in range(0, len(b), width):
        chunk = b[i:i + width]
        hx = " ".join("%02X" % c for c in chunk)
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        out.append("  %08X  %-47s  %s" % (base + i, hx, asc))
    return "\n".join(out)


def main():
    pe = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PE
    data, secs = parse_pe(pe)

    text = next(s for s in secs if s["name"] == ".text")
    textbuf = data[text["raddr"]:text["raddr"] + text["rsize"]]

    # .rdata 里找 printpb / appmsg 相关字符串的 RVA
    rdata = next(s for s in secs if s["name"] == ".rdata")
    rbuf = data[rdata["raddr"]:rdata["raddr"] + rdata["rsize"]]

    interesting = {}
    for kw in [b"printpb", b"<msg>", b"appmsg", b"weixin_printpb", b"mmreader"]:
        positions = []
        start = 0
        while True:
            p = rbuf.find(kw, start)
            if p < 0:
                break
            positions.append(p)
            start = p + 1
            if len(positions) > 30:
                break
        interesting[kw] = positions
        print("rdata %-16s occurrences: %d  first RVAs: %s" % (
            kw.decode(), len(positions),
            ", ".join("0x%X" % (rdata["vaddr"] + p) for p in positions[:5])))

    print("\n" + "=" * 78)
    for name, pat in TARGETS:
        vals, masks = compile_pattern(pat)
        hits = find_all(textbuf, vals, masks)
        print("\n### %s   (%d hit)" % (name, len(hits)))
        for h in hits:
            rva = text["vaddr"] + h
            print("\n  file offset 0x%X   RVA 0x%X" % (text["raddr"] + h, rva))
            lo = max(0, h - 48)
            hi = min(len(textbuf), h + 80)
            print(hexdump(textbuf[lo:hi], text["vaddr"] + lo))
        print()


if __name__ == "__main__":
    main()
