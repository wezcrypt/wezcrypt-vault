<#
.SYNOPSIS
  Build, test and package a WezCrypt Vault release for Windows 10/11 x64.

.DESCRIPTION
  1. Validate Windows environment          10. Build standalone EXE (PyInstaller spec)
  2. Create/reuse build virtual env        11. Verify EXE exists
  3. Install build dependencies            12. Packaged-app smoke test (--self-test)
  4. Install project dependencies          13. Build Inno Setup installer
  5. Run full pytest suite                 14. Verify installer exists
  6. Stop if tests fail                    15. SHA-256 hashes
  7. Expected Windows symlink skips OK     16. Write SHA256SUMS.txt
  8. Secret scan                           17. Print final paths
  9. Clean previous build output safely

  Optional Authenticode signing via environment variables (never stored in the repo):
    WEZCRYPT_SIGN_THUMBPRINT   certificate thumbprint in the Windows certificate store (preferred), or
    WEZCRYPT_SIGN_PFX          path to a .pfx file, with WEZCRYPT_SIGN_PFX_PASSWORD
    WEZCRYPT_SIGN_TIMESTAMP    RFC 3161 timestamp URL (default http://timestamp.digicert.com)
  Without these the build is unsigned and reports: CODE SIGNING: NOT CONFIGURED

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\build_release.ps1
#>
[CmdletBinding()]
param(
    [string]$Python = "",
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Step($n, $text) { Write-Host ""; Write-Host "[$n/17] $text" -ForegroundColor Cyan }
function Fail($text) { Write-Host "ERROR: $text" -ForegroundColor Red; exit 1 }

# ---- 1. Environment ----------------------------------------------------------------------
Step 1 "Validating Windows build environment"
if ($env:OS -ne "Windows_NT") { Fail "This script must run on Windows." }
if (-not [Environment]::Is64BitOperatingSystem) { Fail "A 64-bit Windows is required." }
if (-not $Python) {
    $launcher = Get-Command py -ErrorAction SilentlyContinue
    if ($launcher) { $Python = "py -3.12" } else { $Python = "python" }
}
$pyVersion = & cmd /c "$Python -c ""import sys,struct;print(str(sys.version_info[0])+'.'+str(sys.version_info[1])+' '+str(struct.calcsize('P')*8))""" 2>$null
if (-not $pyVersion) { Fail "Python 3.12+ (64-bit) is required on the BUILD machine only." }
$parts = $pyVersion.Split(" ")
if ([version]$parts[0] -lt [version]"3.12" -or $parts[1] -ne "64") { Fail "Need 64-bit Python >= 3.12, found $pyVersion" }
$Version = (& cmd /c "$Python -c ""import sys;sys.path.insert(0,'.');from wezcrypt_vault.version import __version__;print(__version__)""").Trim()
if ($Version -notmatch '^\d+\.\d+\.\d+$') { Fail "Could not read version from wezcrypt_vault/version.py" }
Write-Host "Version $Version, Python $pyVersion"

# ---- 2-4. Virtual environment + dependencies ------------------------------------------------
Step 2 "Creating/reusing build virtual environment (.venv-build)"
$Venv = Join-Path $Root ".venv-build"
if (-not (Test-Path (Join-Path $Venv "Scripts\python.exe"))) { & cmd /c "$Python -m venv `"$Venv`"" }
$Py = Join-Path $Venv "Scripts\python.exe"
& $Py -m pip install --upgrade pip --quiet
Step 3 "Installing build dependencies"
& $Py -m pip install --quiet "pyinstaller>=6.10,<7" "pytest>=8,<10"
if ($LASTEXITCODE -ne 0) { Fail "pip install (build deps) failed" }
Step 4 "Installing project dependencies"
& $Py -m pip install --quiet -r requirements.txt
if ($LASTEXITCODE -ne 0) { Fail "pip install (requirements) failed" }

# ---- 5-7. Tests ----------------------------------------------------------------------------------
Step 5 "Running full pytest suite"
$env:QT_QPA_PLATFORM = "offscreen"
& $Py -m pytest -v -rs -p no:cacheprovider
$testExit = $LASTEXITCODE
Remove-Item Env:\QT_QPA_PLATFORM
Step 6 "Checking test result"
if ($testExit -ne 0) { Fail "Tests failed - refusing to build a release." }
Step 7 "Skips are reported above (-rs). Only the Windows symlink-privilege skip is expected."

# ---- 8. Secret scan -----------------------------------------------------------------------------------
Step 8 "Scanning project-owned files for secrets"
& $Py scripts\secret_scan.py
if ($LASTEXITCODE -ne 0) { Fail "Secret scan failed." }

# ---- 9. Clean ---------------------------------------------------------------------------------------------
Step 9 "Cleaning previous build output"
foreach ($d in @("build", "dist")) {
    $p = Join-Path $Root $d
    if (Test-Path $p) {
        $resolved = (Resolve-Path $p).Path
        if (-not $resolved.StartsWith($Root)) { Fail "Refusing to delete outside the repository: $resolved" }
        Remove-Item -Recurse -Force $resolved
    }
}

# ---- 10-11. EXE ------------------------------------------------------------------------------------------
Step 10 "Building standalone EXE with PyInstaller"
& $Py -m PyInstaller --noconfirm --clean --distpath dist --workpath build packaging\WezCryptVault.spec
if ($LASTEXITCODE -ne 0) { Fail "PyInstaller failed." }
$Exe = Join-Path $Root "dist\WezCryptVault.exe"
Step 11 "Verifying EXE"
if (-not (Test-Path $Exe)) { Fail "dist\WezCryptVault.exe was not produced." }
$info = (Get-Item $Exe).VersionInfo
Write-Host ("  ProductName={0} ProductVersion={1} FileVersion={2} Company={3}" -f `
    $info.ProductName, $info.ProductVersion, $info.FileVersion, $info.CompanyName)
if ($info.ProductVersion -ne $Version) { Fail "EXE version metadata ($($info.ProductVersion)) != $Version" }

# Optional signing of the EXE before it is wrapped by the installer.
$Signing = "NOT CONFIGURED"
$SignTool = $null
if ($env:WEZCRYPT_SIGN_THUMBPRINT -or $env:WEZCRYPT_SIGN_PFX) {
    $SignTool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
    if (-not $SignTool) { Fail "Signing requested but signtool.exe (Windows SDK) was not found." }
    $ts = if ($env:WEZCRYPT_SIGN_TIMESTAMP) { $env:WEZCRYPT_SIGN_TIMESTAMP } else { "http://timestamp.digicert.com" }
    if ($env:WEZCRYPT_SIGN_THUMBPRINT) {
        $SignArgs = "sign /sha1 $($env:WEZCRYPT_SIGN_THUMBPRINT) /fd sha256 /tr $ts /td sha256"
    } else {
        $SignArgs = "sign /f `"$($env:WEZCRYPT_SIGN_PFX)`" /p `"$($env:WEZCRYPT_SIGN_PFX_PASSWORD)`" /fd sha256 /tr $ts /td sha256"
    }
    & cmd /c "`"$SignTool`" $SignArgs `"$Exe`""
    if ($LASTEXITCODE -ne 0) { Fail "Signing the EXE failed." }
    $Signing = "SIGNED"
}

# ---- 12. Packaged smoke test ---------------------------------------------------------------------
Step 12 "Packaged-app smoke test (real EXE, real Windows Qt platform plugin)"
$Report = Join-Path $Root "build\selftest-report.json"
$proc = Start-Process -FilePath $Exe -ArgumentList @("--self-test", "--report", "`"$Report`"") -PassThru -Wait
if (-not (Test-Path $Report)) {
    Fail "Self-test produced no report (exit $($proc.ExitCode)). A Qt platform plugin or DLL failure is likely."
}
$st = Get-Content $Report -Raw | ConvertFrom-Json
foreach ($c in $st.checks) {
    $mark = if ($c.ok) { "PASS" } else { "FAIL" }
    Write-Host ("  {0}  {1} - {2}" -f $mark, $c.name, $c.detail)
}
if (-not $st.ok -or $proc.ExitCode -ne 0) { Fail "Packaged-app smoke test failed." }
if (-not $st.frozen) { Fail "Self-test did not run inside the frozen EXE." }

# ---- 13-14. Installer ---------------------------------------------------------------------------------
$Installer = Join-Path $Root "dist\WezCryptVault-Setup-$Version.exe"
if (-not $SkipInstaller) {
    Step 13 "Building Inno Setup installer"
    $IsccCmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    $Iscc = if ($IsccCmd) { $IsccCmd.Source } else { $null }
    if (-not $Iscc) {
        foreach ($c in @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe")) {
            if (Test-Path $c) { $Iscc = $c; break }
        }
    }
    if (-not $Iscc) { Fail "Inno Setup 6 (ISCC.exe) not found. Install it from https://jrsoftware.org/isinfo.php" }
    $isccArgs = @("/Qp", "/DAppVersion=$Version", "/DSourceExe=$Exe", "/DOutputDir=$(Join-Path $Root 'dist')")
    if ($SignTool) {
        $isccArgs += "/DSignEnabled"
        $isccArgs += "/Swezsign=`"$SignTool`" $SignArgs `$f"
    }
    $isccArgs += "packaging\WezCryptVault.iss"
    & $Iscc @isccArgs
    if ($LASTEXITCODE -ne 0) { Fail "Inno Setup compilation failed." }
    Step 14 "Verifying installer"
    if (-not (Test-Path $Installer)) { Fail "Installer was not produced: $Installer" }
} else {
    Write-Host "Installer skipped (-SkipInstaller)."
}

# ---- 15-16. Hashes ----------------------------------------------------------------------------------------
Step 15 "Computing SHA-256 hashes"
$Sums = Join-Path $Root "dist\SHA256SUMS.txt"
$lines = @()
foreach ($f in @($Exe, $Installer)) {
    if (Test-Path $f) {
        $h = (Get-FileHash $f -Algorithm SHA256).Hash.ToLower()
        $lines += "$h  $(Split-Path $f -Leaf)"
    }
}
Step 16 "Writing SHA256SUMS.txt"
Set-Content -Path $Sums -Value $lines -Encoding ascii

# ---- 17. Summary --------------------------------------------------------------------------------------------
Step 17 "Release artifacts"
Write-Host "  EXE:        $Exe"
if (Test-Path $Installer) { Write-Host "  Installer:  $Installer" }
Write-Host "  Checksums:  $Sums"
$lines | ForEach-Object { Write-Host "    $_" }
Write-Host "  CODE SIGNING: $Signing"
Write-Host "Done." -ForegroundColor Green


