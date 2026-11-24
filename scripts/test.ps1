# 解析器回归测试
#
# 用真实收款记录（从 monitor.db DPAPI 解密导出）验证 AppMsg 解析器。
# 每次改 AppMsg.cpp / PayParse.cpp 都应该跑一遍。
#
# 用法：powershell -ExecutionPolicy Bypass -File scripts/test.ps1
param(
    [string]$DbPath = "",
    [string]$PyExe  = ""
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$out  = Join-Path $root "build"
New-Item -ItemType Directory -Force $out | Out-Null

# ── 找编译器 ────────────────────────────────────────────────────────
$cc = $null
$winget = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages"
if (Test-Path $winget) {
    $cc = Get-ChildItem $winget -Recurse -Filter "x86_64-w64-mingw32-g++.exe" -ErrorAction SilentlyContinue |
          Select-Object -First 1 -ExpandProperty FullName
}
if (-not $cc) { $cc = (Get-Command x86_64-w64-mingw32-g++ -ErrorAction SilentlyContinue).Source }
if (-not $cc) { Write-Host "找不到 x86_64-w64-mingw32-g++" -ForegroundColor Red; exit 1 }
$env:PATH = "$(Split-Path $cc);$env:PATH"
Write-Host "编译器: $cc" -ForegroundColor Cyan

$flags = @(
    "-std=c++20", "-O1",
    "-DUNICODE", "-D_UNICODE",
    "-finput-charset=UTF-8", "-fexec-charset=UTF-8",
    "-static", "-static-libgcc", "-static-libstdc++",
    "-I", (Join-Path $root "hook\src"),
    "-I", (Join-Path $root "hook\tests")
)

$failed = 0

# ── 1) 合成用例（含负样本）──────────────────────────────────────────
Write-Host "`n[1/2] 合成用例 AppMsgTest" -ForegroundColor Green
$exe1 = Join-Path $out "AppMsgTest.exe"
& $cc @flags -o $exe1 (Join-Path $root "hook\src\AppMsg.cpp") (Join-Path $root "hook\src\AppMsgTest.cpp")
if ($LASTEXITCODE -ne 0) { Write-Host "编译失败" -ForegroundColor Red; exit 1 }

$p1 = Start-Process -FilePath $exe1 -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput "$env:TEMP\am1.txt" -RedirectStandardError "$env:TEMP\am1.err"
Get-Content "$env:TEMP\am1.txt" -Encoding UTF8
if ($p1.ExitCode -ne 0) { $failed++; Write-Host "  ^^ 合成用例有失败" -ForegroundColor Red }

# ── 2) 真实样本（若已导出）──────────────────────────────────────────
$samples = Join-Path $root "hook\tests\samples_generated.h"
if (-not (Test-Path $samples)) {
    Write-Host "`n[2/2] 跳过真实样本：samples_generated.h 不存在" -ForegroundColor Yellow
    Write-Host "  生成方法：" -ForegroundColor Yellow
    Write-Host "    python scripts/export_samples.py [monitor.db 副本路径] hook/tests" -ForegroundColor Yellow
} else {
    Write-Host "`n[2/2] 真实样本 RealSamplesTest" -ForegroundColor Green
    $exe2 = Join-Path $out "RealSamplesTest.exe"
    & $cc @flags -o $exe2 (Join-Path $root "hook\src\AppMsg.cpp") (Join-Path $root "hook\tests\RealSamplesTest.cpp")
    if ($LASTEXITCODE -ne 0) { Write-Host "编译失败" -ForegroundColor Red; exit 1 }

    $p2 = Start-Process -FilePath $exe2 -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput "$env:TEMP\am2.txt" -RedirectStandardError "$env:TEMP\am2.err"
    Get-Content "$env:TEMP\am2.txt" -Encoding UTF8 | Select-Object -Last 20
    if ($p2.ExitCode -ne 0) { $failed++; Write-Host "  ^^ 真实样本有失败" -ForegroundColor Red }
}

# ── 汇总 ────────────────────────────────────────────────────────────
Write-Host ""
if ($failed -eq 0) {
    Write-Host "全部测试通过" -ForegroundColor Green
    exit 0
} else {
    Write-Host "$failed 组测试失败" -ForegroundColor Red
    exit 1
}
