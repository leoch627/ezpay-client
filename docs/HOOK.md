# Hook 原理与运维手册

面向接手维护的人。所有内容都与 `hook/src/` 的实际代码一致。

---

## 1. 完整调用链

```
wxpayclient.exe（网关，管理员运行）
  │
  │ ① 注入巡检（每 injectInterval 秒）
  │    FindProcessByName("Weixin.exe") → 排除已注入的
  │    WxInjectDLL(pid, "wxhook.dll")
  ▼
Weixin.exe
  │ ② LoadLibraryW 触发 DllMain
  │    DllMain 只做一件事：起线程后立刻返回（加载器锁内不能做重活）
  ▼
BootThread
  │ ③ LogInit / SafeReadInit / StatusBoard.Open / SenderStart
  │    BootstrapAsync：最多 40 次、每 0.5~1.5 秒重试一次
  ▼
InstallHooks
  │ ④ FindWeixinModule()：Weixin.dll（4.x）或 WeChatWin.dll（3.x）
  │ ⑤ ScanModule：在可执行节里按特征码扫描
  │ ⑥ RVA 校验：命中位置必须落在预期 RVA ± 1 MB 内
  │ ⑦ ValidatePrologue：确认前 14 字节是可整体搬移的完整指令
  │ ⑧ InlineHook.Install：trampoline + 头部改写
  ▼
微信调用 printpb
  │ ⑨ WxhDetourStub（汇编）
  │    push 8 个易失寄存器 → 传 RegSnapshot* + 原始 rsp 给 WxhCapture
  │    → 恢复寄存器 → jmp *WxhTrampoline（继续原逻辑，零开销路径）
  ▼
WxhCapture
  │ ⑩ 30 ms 节流（同一组寄存器不重复解析）
  │ ⑪ 逐个寄存器当指针试：XML 头命中 → ParseFromAppMsgXml
  │    否则退回 protobuf 遍历（PbWalk）与纯文本
  │ ⑫ 进程内 64 条环形去重（source_key）
  │ ⑬ SenderPush（异步，绝不阻塞微信线程）
  ▼
Sender 工作线程
  │ ⑭ WinHttp POST → 127.0.0.1:29731/hook/payment（3 秒超时）
  ▼
网关 → 去重 → 队列 → 签名 → 上报商户
```

---

## 2. 几个关键设计决策

### 2.1 为什么延迟安装

`DllMain` 运行在**加载器锁**内。在里面扫 113 MB 的 `.text` 会：
- 死锁（任何其他线程的模块加载都会被阻塞）
- 更糟：此时微信自己的重定位还没完成，扫到的字节可能是错的

所以 `DllMain` 只 `CreateThread` 就返回，所有工作在独立线程里做，且**最多重试 40 次**等待模块就绪。

### 2.2 为什么用汇编跳板而不是 C 函数签名

printpb 是微信内部的 C++ 函数（4.x 走 protobuf/XML 序列化），**没有公开签名**，且不同版本的参数布局会变。

如果用 `typedef void (*Fn)(void* ctx, void* msg, int len)` 这种猜测签名去接：
- 栈上第 5 个之后的参数会被破坏（x64 只有 4 个寄存器参数）
- 返回值可能被改
- 微信直接崩

所以 `DetourStub.S` 只做**不改变任何语义**的事：
```asm
pushq rbp, rbx, rsi, rdi, rcx, rdx, r8, r9   ; 8×8=64B，rsp%16 保持 8
subq  $0x28, %rsp                            ; +40B → rsp%16 == 0（call 前必须对齐）
leaq  0x28(%rsp), %rcx                       ; RegSnapshot*
leaq  0x68(%rsp), %rdx                       ; 原始 rsp（栈参数起点）
callq WxhCapture
addq  $0x28, %rsp
popq  r9,r8,rdx,rcx,rdi,rsi,rbx,rbp          ; 逆序复原
jmpq  *WxhTrampoline(%rip)                   ; 尾跳，不留返回地址
```

`RegSnapshot` 字段序（r9, r8, rdx, rcx, rdi, rsi, rbx, rbp）与 push 严格逆序对应。
**改一个必须改另一个。**

### 2.3 为什么特征码这么长

这是本项目踩过最大的坑。

最初的 4 条特征码是从逆向报告里抄的"看起来像 printpb"的字节：

| 特征码 | 在真实 Weixin.dll 4.1.12.53 里的命中数 |
|---|---|
| `48 8D 81 ?? ?? ?? ?? C3` | **104** |
| `48 8D 41 ?? C3` | **65** |
| `48 89 CE 89 11 45 0F 57 C0` | 1（但和下面那条在同一个函数里） |
| `BA 01 00 00 00 F0 0F C1 15 ?? ?? ?? ?? E9` | 1（同上） |

前两条是**通用 x64 函数序言**，任何 100 MB 的模块里都能撞上百处。
`ScanModule` 返回第一个命中 → **必然钩错函数 → 微信崩溃**。

正确的做法（`scripts/find_printpb.py`）：

1. 在 `.rdata` 里找 `weapp_path` 字符串 —— 这是收款 appmsg 独有的字段名，**整个微信模块只出现 1 次**
2. 在 `.text` 里找引用该 RVA 的 `lea reg,[rip+disp32]` 指令
3. 由 xref 回溯到函数入口（跳过 `CC` 填充）
4. 取入口字节**逐步加长**，直到在 113 MB 的 `.text` 里**只命中自身 1 次**

最终得到：

| 特征码 | 长度 | 命中 | 目标 RVA |
|---|---|---|---|
| `weapp_path.A` | 32 B | **1** | `0x48BE1BB` |
| `weapp_path.B` | 28 B | **1** | `0x48BEAA5` |

验证：`python scripts/verify_hook_target.py` → 两条都 `dist=0`，精确落在预期函数入口。

### 2.4 双重判据：特征码 + RVA

特征码唯一还不够 —— 微信一升级，函数会漂。

所以 `Pattern` 结构带 `expectedRva` 和 `rvaTolerance`（默认 1 MB）：

```cpp
ScanHit hit = ScanModule(mod, pats);
if (!hit.rvaOk) {
    // 命中但偏太远 = 别处的同构代码，拒绝安装
    st.SetState(WXHOOK_STATE_VERSION_UNSUPPORTED, "...refusing to hook...");
    return false;
}
```

**宁可报"这个版本不支持"，也不钩错函数。** 前者用户能理解，后者是微信崩溃。

---

## 3. 版本支持矩阵

| 微信版本 | 状态 | 说明 |
|---|---|---|
| 4.1.12.53 | ✅ **实测验证** | 特征码从此版本提取，`verify_hook_target.py` 通过 |
| 4.1.10.31 ~ 4.1.15.x | ⚠️ 预期可用 | RVA 会漂，1 MB 容差内可命中；未逐个实测 |
| 4.1.13.6 | ⚠️ 特殊 | 原程序日志提到"窗口登录受限于 4.1.13.6，登录状态标志位是版本相关" |
| 4.1.48.13 | ❓ 未验证 | 逆向包记录的目标机器版本，但特征未在此版本上验证 |
| 3.x（WeChatWin.dll） | ❌ 不支持 | 代码保留了模块名回退，但无特征码 |

**如何新增版本支持**（微信升级后 hook 失效时）：

```powershell
# 1. 找到新版 Weixin.dll
Get-ChildItem "C:\Program Files\Tencent\Weixin" -Recurse -Filter Weixin.dll

# 2. 定位 weapp_path 引用函数
python scripts\find_printpb.py "<新 Weixin.dll 路径>"

# 3. 提取唯一特征码
#    把上一步输出的候选 RVA 填进 CANDIDATES，然后：
python scripts\extract_signatures.py "<新 Weixin.dll 路径>"

# 4. 把输出的 pattern 加进 Hook.cpp 的 kPrintPbPatterns
#    （旧版本的保留，扫描会按 RVA 校验自动挑合适的）

# 5. 验证
python scripts\verify_hook_target.py "<新 Weixin.dll 路径>"

# 6. 重新编译并实测
scripts\build.ps1
```

---

## 4. 状态码释义

`hook/include/wxhook_abi.h` 的 `wxhook_state`，面板上的"Hook 状态"直接映射：

| 值 | 名称 | 含义 | 怎么办 |
|---|---|---|---|
| 0 | `INIT` | 刚加载，还没开始装 | 等 1~2 秒；一直停在这里说明引导线程卡住 |
| 1 | `MODULE_MISSING` | 当前进程没加载 Weixin.dll | 注入到错进程了，检查 PID |
| 2 | `SCANNING` | 正在扫特征 | 正常，约 0.5~2 秒 |
| 3 | `PATTERN_MISS` | 所有特征都没命中 | 微信版本不支持，按 §3 补特征 |
| 4 | `PROLOGUE_BAD` | 命中了但前导字节不能安全搬移 | 特征可能对但位置偏；看 detail |
| 5 | `TRAMPOLINE_FAIL` | VirtualAlloc 失败 | 内存压力大，重启微信 |
| 6 | `PATCH_FAIL` | VirtualProtect 失败 | 通常是被杀软拦了 |
| 7 | `INSTALLED` | ✅ 装好了 | 正常 |
| 8 | `UNHOOKED` | 已卸载 | 正常（退出时） |
| 9 | `VERSION_UNSUPPORTED` | **命中但 RVA 偏太远，拒绝安装** | 微信升级了，按 §3 补特征 |

`detail` 字段会有具体说明，例如：
```
signature matched at RVA 0x5A1234 but expected ~0x48BE1BB (dist 0x11A679 > tolerance);
refusing to hook to avoid crashing WeChat
```

---

## 5. 共享内存状态板

被注入进程不暴露任何 RPC，只往命名共享内存写：

```
名称：Local\WxPayHookStatus_v1
大小：440 字节（Go 侧有编译期断言 sizeof 必须相等）
魔数：0x57584853 ('WXHS')
```

字段见 `hook/include/wxhook_abi.h` 的 `wxhook_status`。

网关用 `internal/inject` 读它（`ReadHookStatus`），转成面板用的 `model.HookStatus`。
**只读，不写** —— 攻击面为零。

---

## 6. 排障

### 日志在哪

| 日志 | 路径 |
|---|---|
| Hook DLL | `<微信安装目录>\logs\wxpay_hook.log`（超 8 MB 自动截断） |
| 网关 | `data\logs\gateway.log` |
| 同时输出到 | `OutputDebugString`（DebugView 可看） |

### 常见问题

**注入成功但状态一直是 `MODULE_MISSING`**
→ 注错进程了。微信 4.x 有多个 `Weixin.exe` 子进程，只有加载了 `Weixin.dll` 的那个才有效。
   面板上会列出进程列表，挑内存占用最大的那个。

**`PATTERN_MISS` 但微信版本没变**
→ 可能被杀软改了内存，或者微信热更新了 DLL。重启微信再试。

**`VERSION_UNSUPPORTED`，detail 里说 RVA 偏离**
→ 这是**安全行为**，不是 bug。说明微信升级了。按 §3 补特征码。

**装上后微信卡顿**
→ `WxhCapture` 每 30 ms 只解析一次是节流下限。如果 printpb 被调用极其频繁，
   可以调大 `Detour.cpp` 里的节流阈值，或在网关侧把 `source` 改成 `uia` 走不注入路径。

**装钩子瞬间微信崩溃**
→ 说明 `InlineHook.Install` 改写头部时，恰好有线程执行到那段代码。
   当前实现没有 `SuspendThread` 全部线程（见"已知限制"）。概率很低但存在。

---

## 7. 已知限制

| # | 限制 | 影响 | 缓解 |
|---|---|---|---|
| 1 | 改写函数头 14 字节时未挂起其他线程 | 极低概率崩溃 | 无；如需彻底解决要遍历并 `SuspendThread` |
| 2 | `WxhTrampoline` 写入无内存屏障 | 理论上装钩瞬间可能读到 0 | 实际概率极低（安装时采样已短暂停止） |
| 3 | 汇编 stub 缺 `.pdata` 展开信息 | `WxhCapture` 内抛异常会栈展开错 | `WxhCapture` 已设计为不抛异常（全部 `SafeRead` 探针） |
| 4 | 只支持 x64 微信 | x86 微信无法注入 | `WxInjectDLL` 会检测位数并明确报错 |
| 5 | 特征码只对 4.1.12.53 验证过 | 其他版本可能 `VERSION_UNSUPPORTED` | 按 §3 补特征 |
| 6 | `PayParse` 与 `AppMsg` 两套 XML 解析并存 | 维护时可能改错一处 | `PayParse` 是运行时主路径；`AppMsg` 只做回归对拍，两者都用真实样本验证 |
| 7 | 未实现"禁止微信自动更新" | 微信升级会导致 hook 失效 | 配置项存在但为桩，见 cmd/agent 的 injectLoop 与代理日志 `[wechat.update]` |

---

## 8. 安全边界

这套实现有意划定了几条线：

1. **只读，不写目标进程的业务数据**
   所有内存访问走 `ReadProcessMemory` 探针（`SafeRead.cpp`），失败返回 false，不抛异常。
   唯一的写操作是安装 hook 时改写目标函数头 14 字节（这是"钩子"的定义，无法避免）。

2. **不修改微信的任何逻辑**
   跳板执行完 `WxhCapture` 后原样恢复寄存器并尾跳回原逻辑。
   `WxhCapture` 的返回值被忽略，即使解析失败也不影响微信行为。

3. **装不上就放弃**
   RVA 偏太远、前导字节不安全、VirtualProtect 失败 —— 一律 `return false` + 写状态，不强行 patch。

4. **状态只单向暴露**
   共享内存只读；被注入进程不监听端口、不接受命令。

5. **不碰登录态**
   不读 cookie、不读 token、不调登录接口。只关心"收款到账"这一条消息的内容。
