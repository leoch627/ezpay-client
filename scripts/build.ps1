# wxhook.dll / wxinject.dll 构建脚本
# 用法：pwsh -ExecutionPolicy Bypass -File scripts\build.ps1
#       pwsh -File scripts\build.ps1 -Clean
#
# 依赖：LLVM-MinGW（winget install MartinStorsjo.LLVM-MinGW.UCRT）
#       或任意 x86_64-w64-mingw32-g++ / clang++
#
# 说明（踩过的坑，别改回去）：
#   1. 编译器必须用 g++ 驱动（x86_64-w64-mingw32-g++.exe），它会自动带上
#      -target x86_64-w64-windows-gnu 和 UCRT 头文件路径；裸 clang.exe 不会。
#   2. 所有链接库走命令行：MinGW 不认 #pragma comment(lib, ...)。
#   3. 参数一律用数组 @argv 传递。PowerShell 会把 -Wl,--no-insert-timestamp
#      里的逗号当数组分隔符解析，裸写必然出错。
#   4. 不要加 -Wl,--exclude-all-symbols 到 wxhook；它会连 __declspec(dllexport)
#      一起吞掉。只有 wxinject 用了显式导出宏，可以加。

param(
    [string]$Config = "Release",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$src  = Join-Path $root "hook\src"
$inc  = Join-Path $root "hook\include"
$out  = Join-Path $root "build"

# ── 找编译器 ─────────────────────────────────────────────────────────
function Find-Compiler {
    # 1) winget 安装的 LLVM-MinGW（路径里带 _Microsoft.Winget.Source_ 哈希，不能写死）
    $wingetRoots = @(
        (Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages"),
        (Join-Path $env:ProgramFiles  "WinGet\Packages"),
        (Join-Path ${env:ProgramFiles(x86)} "WinGet\Packages")
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($wr in $wingetRoots) {
        # 优先 g++.exe（clang 封装，带完整 target/头文件配置）
        $hit = Get-ChildItem $wr -Recurse -Filter "x86_64-w64-mingw32-g++.exe" `
                   -ErrorAction SilentlyContinue -File |
               Where-Object { $_.DirectoryName -match 'llvm-mingw' } |
               Sort-Object FullName -Descending |
               Select-Object -First 1
        if ($hit) { return $hit.FullName }

        # 退一步：只要有 llvm-mingw 目录就直接拼
        $dir = Get-ChildItem $wr -Recurse -Directory -Filter "llvm-mingw-*-ucrt-x86_64" `
                   -ErrorAction SilentlyContinue |
               Sort-Object FullName -Descending |
               Select-Object -First 1
        if ($dir) {
            $cand = Join-Path $dir.FullName "bin\x86_64-w64-mingw32-g++.exe"
            if (Test-Path $cand) { return $cand }
        }
    }

    # 2) PATH 里现成的
    foreach ($n in @("x86_64-w64-mingw32-g++.exe", "x86_64-w64-mingw32-gcc.exe",
                     "x86_64-w64-mingw32-clang++.exe", "g++.exe", "clang++.exe")) {
        $c = Get-Command $n -ErrorAction SilentlyContinue
        if ($c) { return $c.Source }
    }

    # 3) 常见手动安装位置
    foreach ($p in @("C:\llvm-mingw\bin", "C:\msys64\mingw64\bin", "C:\mingw64\bin")) {
        $cand = Join-Path $p "x86_64-w64-mingw32-g++.exe"
        if (Test-Path $cand) { return $cand }
    }
    return $null
}

function Find-Objdump([string]$ccPath) {
    $dir = Split-Path $ccPath
    foreach ($n in @("llvm-objdump.exe", "x86_64-w64-mingw32-objdump.exe", "objdump.exe")) {
        $cand = Join-Path $dir $n
        if (Test-Path $cand) { return $cand }
    }
    $g = Get-Command "llvm-objdump.exe" -ErrorAction SilentlyContinue
    if ($g) { return $g.Source }
    return $null
}

$cc = Find-Compiler
if (-not $cc) {
    Write-Host "找不到 x86_64 C++ 编译器。请先执行：" -ForegroundColor Red
    Write-Host '  winget install --id MartinStorsjo.LLVM-MinGW.UCRT --accept-package-agreements --accept-source-agreements' -ForegroundColor Yellow
    exit 1
}
$ccDir = Split-Path $cc
$env:PATH = "$ccDir;$env:PATH"      # .S 预处理要能调到同目录的 clang
Write-Host "编译器 : $cc" -ForegroundColor Cyan
Write-Host "输出   : $out" -ForegroundColor Cyan

if ($Clean -and (Test-Path $out)) {
    # 只删本脚本自己的产物。build/ 下还有 e2e/、obj/ 等别的目标在用，
    # 整个目录 Remove-Item -Recurse 会撞上别人正打开的文件（mock.err 之类），
    # 也会误删不属于我们的东西。
    foreach ($f in @("wxhook.dll", "wxinject.dll", "wxhook.lib", "wxinject.lib")) {
        $p = Join-Path $out $f
        if (Test-Path $p) { Remove-Item $p -Force -ErrorAction SilentlyContinue }
    }
}
New-Item -ItemType Directory -Force $out | Out-Null

# ── 通用编译参数（数组，绝不裸拼）────────────────────────────────────
$common = @(
    "-std=c++20", "-O2", "-Wall", "-Wextra",
    "-DUNICODE", "-D_UNICODE", "-DWIN32_LEAN_AND_MEAN", "-DNOMINMAX",
    "-I", $inc,
    # 源码里有中文字面量（收款关键词、日志）。显式钉死 UTF-8，
    # 否则在 GBK 代码页的机器上 exec charset 会把字面量编成 GBK 字节，
    # 与微信运行时给的 UTF-8 文本永远匹配不上。
    "-finput-charset=UTF-8", "-fexec-charset=UTF-8",
    "-static-libgcc", "-static-libstdc++",
    "-Wl,--no-insert-timestamp"
)

$hookSources = @(
    "Log.cpp", "Pattern.cpp", "Trampoline.cpp", "PbWalk.cpp", "PayParse.cpp",
    "Status.cpp", "Sender.cpp", "SafeRead.cpp", "Detour.cpp", "DetourStub.S",
    "Hook.cpp", "DllMain.cpp",
    # AppMsg 是独立于 PayParse 的对拍实现（Am* 前缀，故意不合并）。
    # 主路径仍走 PayParse::ParseFromAppMsgXml，AppMsg 只做回归参考。
    "AppMsg.cpp"
) | ForEach-Object { Join-Path $src $_ }

$injectSources = @("Log.cpp", "Inject.cpp") | ForEach-Object { Join-Path $src $_ }

$failed = @()

function Invoke-Build {
    param([string]$Label, [string]$OutFile, [string[]]$Sources, [string[]]$Libs, [string[]]$Extra)

    Write-Host "`n[$Label] -> $(Split-Path -Leaf $OutFile)" -ForegroundColor Green
    $argv = @() + $common + @("-shared", "-o", $OutFile) + $Sources + $Libs + $Extra

    # 关键：原生程序往 stderr 写东西时，若 $ErrorActionPreference = 'Stop'，
    # `2>&1` 合并出来的记录会被当成终止错误直接抛出，编译"失败"于是一条 warning。
    # 这里局部降级为 Continue，用完立刻还原。
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $log  = & $cc @argv 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prevEap

    # 只把 error 打全，warning 折叠成计数
    $errLines = $log | Where-Object { $_ -match ':\s*error:' }
    $warnCnt  = ($log | Where-Object { $_ -match ':\s*warning:' }).Count
    if ($warnCnt -gt 0) { Write-Host "  warning x$warnCnt（允许保留）" -ForegroundColor DarkYellow }

    if ($code -ne 0 -or $errLines) {
        Write-Host "  编译失败 exit=$code" -ForegroundColor Red
        $errLines | Select-Object -First 40 | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
        if (-not $errLines) { $log | Select-Object -First 40 | ForEach-Object { Write-Host "    $_" } }
        return $false
    }
    if (-not (Test-Path $OutFile)) {
        Write-Host "  未产出文件" -ForegroundColor Red
        return $false
    }
    $size = (Get-Item $OutFile).Length
    if ($size -lt 100KB) {
        Write-Host ("  产物仅 {0:N0} B（预期 > 100KB，可能是空壳）" -f $size) -ForegroundColor Red
        return $false
    }
    Write-Host ("  OK  {0:N0} B" -f $size) -ForegroundColor Green
    return $true
}
$hookOut   = Join-Path $out "wxhook.dll"
$injectOut = Join-Path $out "wxinject.dll"

# wxhook：不加 --exclude-all-symbols（会吞掉 dllexport）
$hookOk = Invoke-Build -Label "1/2 wxhook" -OutFile $hookOut `
    -Sources $hookSources `
    -Libs @("-lwinhttp", "-lbcrypt", "-lpsapi", "-ladvapi32") `
    -Extra @("-Wl,--kill-at")
if (-not $hookOk) { $failed += "wxhook.dll" }

# wxinject：Inject.h 里每个导出都带了 __declspec(dllexport)，
# 可以安全开 --exclude-all-symbols，把 wxh::Log* 那堆 C++ 修饰名挡在导出表外。
$injectOk = Invoke-Build -Label "2/2 wxinject" -OutFile $injectOut `
    -Sources $injectSources `
    -Libs @("-lpsapi", "-ladvapi32") `
    -Extra @("-Wl,--kill-at", "-Wl,--exclude-all-symbols")
if (-not $injectOk) { $failed += "wxinject.dll" }

# ── 导出表自检 ───────────────────────────────────────────────────────
$expect = @{
    "wxhook.dll"   = @("WxHookInstall", "WxHookUninstall", "WxHookQueryStatus", "WxHookPostTest")
    "wxinject.dll" = @("WxInjectDLL", "WxFindProcessByName", "WxGetModuleBase", "WxFindWeChatExe")
}

$od = Find-Objdump $cc
if ($od) {
    foreach ($name in @("wxhook.dll", "wxinject.dll")) {
        $p = Join-Path $out $name
        if (-not (Test-Path $p)) { continue }

        Write-Host "`n$name 导出表：" -ForegroundColor Cyan
        $dump = & $od -p $p 2>&1 | Out-String
        $rows = $dump -split "`r?`n" | Where-Object { $_ -match '^\s+\d+\s+0x[0-9a-fA-F]+\s+\S' }
        $rows | ForEach-Object { Write-Host "  $_" }

        foreach ($want in $expect[$name]) {
            if ($dump -notmatch "\b$([regex]::Escape($want))\b") {
                Write-Host "  缺少导出: $want" -ForegroundColor Red
                if ($failed -notcontains $name) { $failed += $name }
            }
        }
    }
} else {
    Write-Host "未找到 objdump，跳过导出表校验" -ForegroundColor DarkYellow
}

# ── 汇总 ─────────────────────────────────────────────────────────────
Write-Host ""
if ($failed.Count -gt 0) {
    Write-Host "构建失败: $($failed -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host "构建成功，产物：" -ForegroundColor Green
Get-ChildItem $out -Filter "*.dll" | ForEach-Object {
    "  {0,-16} {1,10:N0} B" -f $_.Name, $_.Length
}
exit 0
