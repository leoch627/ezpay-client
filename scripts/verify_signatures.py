"""
在真实 Weixin.dll 上验证 Hook.cpp 里的 printpb 特征码。

目的：dll-builder 指出这 4 条特征码是"通用 x64 函数序言"，会在任何大模块里撞上成百上千次。
如果真是这样，ScanModule 取第一个命中点必然钩错函数，装上就是微信崩溃。

本脚本统计每条特征在真实 Weixin.dll 可执行节里的命中次数。
只有命中次数 = 1 的才有资格当特征码。

用法：python verify_signatures.py [Weixin.dll 路径]
"""
import struct
import sys

DEFAULT_PE = r"C:\Program Files\Tencent\Weixin\4.1.12.53\Weixin.dll"

PATTERNS = [
    ("printpb.lea-rax-rcx-disp-ret",  "48 8D 81 ?? ?? ?? ?? C3"),
    ("printpb.lea-rax-rcx-disp8-ret", "48 8D 41 ?? C3"),
    ("printpb.mov-esi-ecx-stor",      "48 89 CE 89 11 45 0F 57 C0"),
    ("printpb.call-jmp-thunk",        "BA 01 00 00 00 F0 0F C1 15 ?? ?? ?? ?? E9"),
]


def parse_pe_sections(path):
    with open(path, "rb") as f:
        data = f.read()

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError("not PE")

    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec_off = e_lfanew + 24 + opt_size

    sections = []
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, o + 8)
        chars = struct.unpack_from("<I", data, o + 36)[0]
        sections.append({
            "name": name, "vsize": vsize, "vaddr": vaddr,
            "rsize": rsize, "raddr": raddr, "chars": chars,
            "exec": bool(chars & 0x20000000),
        })
    return data, sections


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


def count_hits(buf, vals, masks):
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
        ok = True
        for i in range(n):
            if (buf[base + i] & masks[i]) != (vals[i] & masks[i]):
                ok = False
                break
        if ok:
            hits.append(base)
    return hits


def main():
    pe = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PE

    data, sections = parse_pe_sections(pe)
    print("file: %s" % pe)
    print("size: %.1f MB" % (len(data) / 1024 / 1024))
    print("sections:")
    for s in sections:
        if s["exec"]:
            print("  %-10s VA=0x%08X VSize=0x%08X Raw=0x%08X EXEC" % (
                s["name"], s["vaddr"], s["vsize"], s["raddr"]))

    # 只扫可执行节
    exec_buf = b""
    for s in sections:
        if not s["exec"]:
            continue
        exec_buf += data[s["raddr"]:s["raddr"] + s["rsize"]]

    print("\nexecutable bytes: %.1f MB" % (len(exec_buf) / 1024 / 1024))
    print("=" * 78)
    print("signature hit count (uniqueness check)")
    print("=" * 78)

    summary = []
    for name, text in PATTERNS:
        vals, masks = compile_pattern(text)
        hits = count_hits(exec_buf, vals, masks)
        if len(hits) == 1:
            verdict = "UNIQUE - usable"
        elif len(hits) > 1:
            verdict = "AMBIGUOUS - %d hits, would hook wrong function" % len(hits)
        else:
            verdict = "MISS - not found"
        summary.append((name, len(hits), verdict))

        print("\n%s" % name)
        print("  pattern: %s" % text)
        print("  hits: %d  ->  %s" % (len(hits), verdict))

    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)
    for name, n, verdict in summary:
        print("  %-34s %8d   %s" % (name, n, verdict))

    usable = sum(1 for _, n, _ in summary if n == 1)
    print("\nusable signatures: %d / %d" % (usable, len(PATTERNS)))
    return 0 if usable == len(PATTERNS) else 1


if __name__ == "__main__":
    sys.exit(main())
