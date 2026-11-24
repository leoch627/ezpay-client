"""
从真实 Weixin.dll 里定位 printpb 相关代码。

思路（不依赖符号表，因为微信 stripped）：
  1. 在 .rdata 找 appmsg / <msg> / mmreader 等字符串的 RVA
  2. 在 .text 里找"引用该 RVA 的指令"（x64 lea reg,[rip+disp32]）
  3. 这些指令所在函数就是处理 appmsg 的函数
  4. 输出函数入口 RVA + 入口处 16 字节（作为特征码素材）+ 引用点附近的指令

这样得到的特征码是"真的会处理收款 XML 的代码"，而不是通用序言。
"""
import struct
import sys

DEFAULT_PE = r"C:\Program Files\Tencent\Weixin\4.1.12.53\Weixin.dll"

# 候选锚点字符串：收款 appmsg 一定会有这些
ANCHORS = [
    b"<msg>",
    b"mmreader",
    b"weapp_path",
    b"mini-receipt",
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
                     "rsize": rsize, "raddr": raddr,
                     "exec": bool(chars & 0x20000000)})
    return data, secs


def sec_by_name(secs, name):
    return next((s for s in secs if s["name"] == name), None)


def find_string_rvas(data, rdata, anchors):
    """返回 {string: [rva,...]}，最多每个字符串取 20 个"""
    rbuf = data[rdata["raddr"]:rdata["raddr"] + rdata["rsize"]]
    out = {}
    for a in anchors:
        hits = []
        start = 0
        while len(hits) < 20:
            p = rbuf.find(a, start)
            if p < 0:
                break
            hits.append(rdata["vaddr"] + p)
            start = p + 1
        out[a] = hits
    return out


def find_xrefs(textbuf, text_va, target_rva, window=0x80000000):
    """
    在 .text 里找把 target_rva 作为 rip 相对目标引用的指令。
    支持：
      48 8D xx <disp32>   lea reg,[rip+disp]     (48 8D /r)
      48 8B xx <disp32>   mov reg,[rip+disp]     (48 8B /r)
      4C 8D xx <disp32>   lea r8-r15,[rip+disp]
      4C 8B xx <disp32>   mov r8-r15,[rip+disp]
      8D xx <disp32> / 8B xx <disp32>（无 REX）
    """
    out = []
    n = len(textbuf)
    # 逐个位置检查是否构成 rip 相对引用
    for i in range(0, n - 8):
        b0 = textbuf[i]

        # 判断 opcode 形态
        rex = 0
        j = i
        if b0 in (0x48, 0x4C, 0x49, 0x4D):
            rex = b0
            j = i + 1
            if j >= n:
                continue
            op = textbuf[j]
            if op not in (0x8D, 0x8B):
                continue
            modrm_idx = j + 1
        elif b0 in (0x8D, 0x8B):
            op = b0
            modrm_idx = i + 1
        else:
            continue

        if modrm_idx >= n:
            continue
        modrm = textbuf[modrm_idx]
        # 必须是 RIP-relative: mod=00, rm=101
        if (modrm & 0xC7) != 0x05:
            continue

        disp_idx = modrm_idx + 1
        if disp_idx + 4 > n:
            continue
        disp = struct.unpack_from("<i", textbuf, disp_idx)[0]

        # 指令结束位置 = disp 之后
        next_ip = text_va + disp_idx + 4
        target = (next_ip + disp) & 0xFFFFFFFFFFFFFFFF
        if target != target_rva:
            continue

        # 找到这条指令所属函数的入口：往前找最近的 int3 填充 + push 序言
        func_start = find_function_start(textbuf, i)
        out.append({
            "xref_rva": text_va + i,
            "func_rva": text_va + func_start,
            "insn_off": i,
            "rex": rex,
            "op": op,
        })
        if len(out) > 60:
            break
    return out


def find_function_start(buf, off):
    """
    从 off 往回找函数入口。
    MSVC 风格：函数之间用 CC (int3) 或 90 (nop) 填充。
    返回入口在 buf 中的偏移。
    """
    i = off
    limit = max(0, off - 0x4000)
    while i > limit:
        if buf[i] == 0xCC:
            # 连续 CC 之后就是入口
            j = i
            while j > limit and buf[j] == 0xCC:
                j -= 1
            return j + 1
        i -= 1
    return off


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
    text = sec_by_name(secs, ".text")
    rdata = sec_by_name(secs, ".rdata")

    textbuf = data[text["raddr"]:text["raddr"] + text["rsize"]]
    print("file: %s" % pe)
    print(".text  VA=0x%X size=%.1f MB" % (text["vaddr"], text["rsize"] / 1024 / 1024))
    print(".rdata VA=0x%X size=%.1f MB" % (rdata["vaddr"], rdata["rsize"] / 1024 / 1024))

    str_rvas = find_string_rvas(data, rdata, ANCHORS)

    print("\n" + "=" * 78)
    print("anchor strings in .rdata")
    print("=" * 78)
    for a in ANCHORS:
        hits = str_rvas[a]
        print("  %-16s %d found: %s" % (
            a.decode(), len(hits),
            ", ".join("0x%X" % h for h in hits[:6])))

    print("\n" + "=" * 78)
    print("code referencing those strings (.text xrefs)")
    print("=" * 78)

    all_funcs = {}
    for a in ANCHORS:
        for s_rva in str_rvas[a][:6]:
            xrefs = find_xrefs(textbuf, text["vaddr"], s_rva)
            if not xrefs:
                continue
            print("\n-> '%s' @ RVA 0x%X  (%d xrefs)" % (a.decode(), s_rva, len(xrefs)))
            for x in xrefs[:8]:
                fr = x["func_rva"]
                all_funcs.setdefault(fr, []).append(a.decode())
                off = fr - text["vaddr"]
                entry = textbuf[off:off + 24] if 0 <= off < len(textbuf) else b""
                entry_hex = " ".join("%02X" % c for c in entry)
                print("   xref@0x%X  func@0x%X  entry: %s" % (
                    x["xref_rva"], fr, entry_hex))

    print("\n" + "=" * 78)
    print("candidate functions (sorted by number of distinct anchors)")
    print("=" * 78)
    ranked = sorted(all_funcs.items(), key=lambda kv: -len(set(kv[1])))
    for fr, anchors in ranked[:15]:
        off = fr - text["vaddr"]
        entry = textbuf[off:off + 32] if 0 <= off < len(textbuf) else b""
        print("\n  func RVA 0x%X   anchors=%s" % (fr, ",".join(sorted(set(anchors)))))
        print(hexdump(entry, fr))


if __name__ == "__main__":
    main()
