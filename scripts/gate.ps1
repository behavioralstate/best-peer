# The local proof of SDLC.md section 3, on Windows: the same steps as scripts/gate.sh, which is the one that CI runs,
# ending in GATE GREEN or GATE RED. Cargo runs inside the MSVC Build Tools environment when that is installed (rustc
# otherwise picks another Visual Studio on the machine and finds no libraries). The validator's version is read from
# gate.sh, so the two scripts cannot drift. The peers listen on 127.0.0.1:7791 to 7796, away from a peer already
# serving on 7777.
#
#   pwsh scripts/gate.ps1 [fmt|clippy|test|build|validate|all]      default: all
param([string]$What = "all")
if ($What -notin "fmt", "clippy", "test", "build", "validate", "all") { "scripts/gate.ps1: unknown step '$What'; one of fmt, clippy, test, build, validate, all"; "GATE RED"; exit 1 }
$repo = Split-Path -Parent $PSScriptRoot
$bt = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools"
if (Test-Path "$bt\VC\Auxiliary\Build\vcvars64.bat") {
    cmd /c "`"$bt\VC\Auxiliary\Build\vcvars64.bat`" >nul 2>&1 && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
    }
}
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
Set-Location $repo
$validate = (Select-String -Path "$repo\scripts\gate.sh" -Pattern '^BEST_VALIDATE_VERSION=(\S+)' | Select-Object -First 1).Matches[0].Groups[1].Value
if (-not $validate) { throw "scripts/gate.sh names no BEST_VALIDATE_VERSION" }
$failed = $false
# A step's verdict is the command's own exit code, captured before any filter runs over its output.
function Step($name, [scriptblock]$body) {
    "=== $name"; & $body; if ($LASTEXITCODE -ne 0) { $script:failed = $true; "FAILED: $name" }
}
function Run([string[]]$cmd, [scriptblock]$show) {
    $out = & $cmd[0] $cmd[1..($cmd.Length - 1)] 2>&1; $code = $LASTEXITCODE
    $out | & $show; $global:LASTEXITCODE = $code
}
if ($What -in "all", "fmt") { Step "fmt" { Run @("cargo", "fmt", "--all", "--check") { $input | Select-Object -Last 3 } } }
if ($What -in "all", "clippy") { Step "clippy" { Run @("cargo", "clippy", "--workspace", "--all-targets", "--", "-D", "warnings") { $input | Select-String -Pattern '^(error|warning: unused)' -Context 0,6 | Select-Object -First 3 } } }
if ($What -in "all", "test") { Step "test" { Run @("cargo", "test", "--workspace") { $input | Select-String -Pattern 'test result|^error|panicked' } } }
if ($What -in "all", "build", "validate") { Step "release build" { Run @("cargo", "build", "--release", "-p", "best-peer") { $input | Select-Object -Last 1 } } }
if ($What -in "all", "validate") {
    Step "validate, anonymous" {
        $data = Join-Path ([System.IO.Path]::GetTempPath()) ("best-peer-validate-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
        New-Item -ItemType Directory -Path $data | Out-Null
        $env:BEST_PEER_RUNTIME = "fake"
        $env:BEST_PEER_GPU = "none"
        $env:BEST_PEER_DATA = $data
        $env:BEST_PEER_LISTEN = "127.0.0.1:7791"
        $env:BEST_PEER_ENDPOINT = "http://127.0.0.1:7791"
        $p = Start-Process -FilePath .\target\release\best-peer.exe -PassThru -WindowStyle Hidden
        try {
            # The process is checked before the port is trusted: a peer left on the port by an earlier run would
            # answer in place of the one that could not bind, and the gate would validate the wrong binary.
            $up = $false
            for ($i = 0; $i -lt 60 -and -not $up -and -not $p.HasExited; $i++) {
                Start-Sleep -Milliseconds 500
                try { Invoke-RestMethod -Uri "http://127.0.0.1:7791/.well-known/best" -ErrorAction Stop | Out-Null; $up = $true } catch {}
            }
            if ($up) {
                npx -y "@behavioralstate/best-validate@$validate" http://127.0.0.1:7791 2>&1 | Select-String -Pattern 'FAIL|WARN|CONFORMANT'
                $code = $LASTEXITCODE
            } elseif ($p.HasExited) { "the peer for 127.0.0.1:7791 exited before it answered"; $code = 1 }
            else { "the peer at 127.0.0.1:7791 did not answer"; $code = 1 }
        } finally {
            if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force; $p.WaitForExit(5000) | Out-Null }
            Remove-Item -Recurse -Force $data -ErrorAction SilentlyContinue
        }
        $global:LASTEXITCODE = $code
    }
    Step "validate, signed in over https, with the registration probe" { pwsh -NoProfile -File "$PSScriptRoot\gate\validate-signed-in.ps1" 2>&1 | Select-Object -Last 8 }
    Step "validate, a workspace with a cloud over two members" { pwsh -NoProfile -File "$PSScriptRoot\gate\validate-cloud.ps1" 2>&1 | Select-Object -Last 10 }
}
if ($failed) { "GATE RED"; exit 1 } else { "GATE GREEN"; exit 0 }
