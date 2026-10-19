# The cloud lane of scripts/gate.ps1: two member peers on the fakes and a door, the workspace made and the cloud
# configured through the surface (create-workspace at the root, configure-cloud in the workspace), each member
# admitting the cloud through the real `best-peer approve` with the code the door logs, then best-validate on the root
# with the workspace's manifest (--tenant), anonymous and signed in with the registration probe. Exit 0 only when both
# say CONFORMANT, both members are up in the workspace's clouds, and BEST_PEER_MEMBERS is refused with the fix.
# The same lane as lane_cloud in scripts/gate.sh.
$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = "$repo\target\release\best-peer.exe"
$validate = (Select-String -Path "$repo\scripts\gate.sh" -Pattern '^BEST_VALIDATE_VERSION=(\S+)' | Select-Object -First 1).Matches[0].Groups[1].Value
if (-not $validate) { throw "scripts/gate.sh names no BEST_VALIDATE_VERSION" }
$root = Join-Path ([System.IO.Path]::GetTempPath()) ("best-peer-ws-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$dirs = @{ a = Join-Path $root "a"; b = Join-Path $root "b"; door = Join-Path $root "door"; old = Join-Path $root "old" }
$dirs.Values | ForEach-Object { New-Item -ItemType Directory -Path $_ | Out-Null }
$ports = @{ a = 7793; b = 7794; door = 7795; old = 7796 }
$procs = @{}
function Start-Door([string]$name, [hashtable]$extra) {
    $env = @{ BEST_PEER_DATA = $dirs[$name]; BEST_PEER_LISTEN = "127.0.0.1:$($ports[$name])"; BEST_PEER_ENDPOINT = "http://127.0.0.1:$($ports[$name])"; BEST_PEER_RUNTIME = "fake"; BEST_PEER_GPU = "none" }
    foreach ($k in $extra.Keys) { $env[$k] = $extra[$k] }
    $procs[$name] = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $dirs[$name] "log") -RedirectStandardError (Join-Path $dirs[$name] "err") -Environment $env
}
function Wait-Manifest([string]$name) {
    # Returns the boolean alone; the diagnostics go to the host, since anything else written here would join the
    # output and make `-not (Wait-Manifest ...)` false whatever the verdict.
    foreach ($i in 1..60) {
        Start-Sleep -Milliseconds 500
        try { Invoke-RestMethod -Uri "http://127.0.0.1:$($ports[$name])/.well-known/best" -ErrorAction Stop | Out-Null; return $true } catch {}
        if ($procs[$name].HasExited) { break }
    }
    Write-Host "the $name door is not up:"
    Get-Content (Join-Path $dirs[$name] "log") -ErrorAction SilentlyContinue | Write-Host
    Get-Content (Join-Path $dirs[$name] "err") -ErrorAction SilentlyContinue | Write-Host
    return $false
}
function Send-Command([string]$base, [string]$key, [string]$id, [string]$type, [string]$schema, [hashtable]$data) {
    $envelope = @{ specversion = "1.0"; id = $id; source = "https://gate.test/agent"; type = $type; datacontenttype = "application/json"; dataschema = "$base/commands/$schema/1.0"; time = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); data = $data } | ConvertTo-Json -Depth 6 -Compress
    Invoke-RestMethod -Method Post -Uri "$base/commands" -Headers @{ "X-Api-Key" = $key } -ContentType "application/cloudevents+json" -Body $envelope | Out-Null
}
try {
    Start-Door "a" @{}
    Start-Door "b" @{}
    Start-Door "door" @{}
    if (-not (Wait-Manifest "a") -or -not (Wait-Manifest "b") -or -not (Wait-Manifest "door")) { exit 1 }
    $base = "http://127.0.0.1:$($ports.door)"
    $manifest = Invoke-RestMethod -Uri "$base/.well-known/best"
    if (-not $manifest.best.tenants.manifest.EndsWith("/.well-known/best/{tenantId}")) { "the root manifest declares no tenant template"; exit 1 }
    $env:BEST_PEER_DATA = $dirs.door
    $device = Invoke-RestMethod -Method Post -Uri "$base/auth/device" -ContentType "application/x-www-form-urlencoded" -Body @{ client_id = "gate"; connection = "gate-door"; agent_label = "the gate" }
    "approve on the door: " + (& $exe approve $device.user_code 2>&1)
    $token = Invoke-RestMethod -Method Post -Uri "$base/auth/token" -ContentType "application/x-www-form-urlencoded" -Body @{ grant_type = "urn:ietf:params:oauth:grant-type:device_code"; device_code = $device.device_code; client_id = "gate" }
    $key = $token.access_token
    Send-Command $base $key "gate-ws" "CreateWorkspace" "create-workspace" @{ name = "Gate" }
    $ws = $null
    foreach ($i in 1..40) {
        $w = Invoke-RestMethod -Uri "$base/queries/get-workspaces" -Headers @{ "X-Api-Key" = $key }
        if ($w.workspaces.Count -gt 0) { $ws = $w.workspaces[0].workspace; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ws) { "no workspace after create-workspace:"; Get-Content (Join-Path $dirs.door "log"); exit 1 }
    "workspace: $ws"
    $tenant = "$base/workspaces/$ws"
    Send-Command $tenant $key "gate-cloud" "ConfigureCloud" "configure-cloud" @{ cloud = "lab"; members = @(@{ peer = "a"; endpoint = "http://127.0.0.1:$($ports.a)" }, @{ peer = "b"; endpoint = "http://127.0.0.1:$($ports.b)" }) }
    # The cloud asks each member to admit it and logs the code; the operator of each member approves it there.
    $log = Join-Path $dirs.door "log"
    foreach ($m in "a", "b") {
        $code = $null
        foreach ($i in 1..40) {
            $hit = Select-String -Path $log -Pattern "on $m, run on that machine: best-peer approve (\S+)" | Select-Object -First 1
            if ($hit) { $code = $hit.Matches[0].Groups[1].Value; break }
            Start-Sleep -Milliseconds 500
        }
        if (-not $code) { "the cloud asked $m for no code:"; Get-Content $log; exit 1 }
        $env:BEST_PEER_DATA = $dirs[$m]
        "approve on ${m}: " + (& $exe approve $code 2>&1)
    }
    $up = 0
    foreach ($i in 1..60) {
        $clouds = Invoke-RestMethod -Uri "$tenant/queries/get-clouds" -Headers @{ "X-Api-Key" = $key }
        $up = @($clouds.clouds[0].peers | Where-Object { $_.state -eq "up" }).Count
        if ($up -eq 2) { break }
        Start-Sleep -Milliseconds 500
    }
    $hs = Invoke-RestMethod -Uri "$tenant/queries/get-hardware-state" -Headers @{ "X-Api-Key" = $key }
    $ids = @($hs.devices | ForEach-Object { $_.id })
    "workspace hardware: peers up=$up devices=" + ($ids -join ",")
    if ($up -ne 2) { Get-Content $log; exit 1 }
    if (($ids -join ",") -ne "lab/a/cpu-0,lab/b/cpu-0") { "the workspace lists the wrong devices: $($ids -join ',')"; exit 1 }
    "=== best-validate on the root and the workspace's manifest, anonymous"
    npx -y "@behavioralstate/best-validate@$validate" $base --tenant $ws 2>&1 | Select-String -Pattern 'FAIL|WARN|CONFORMANT'
    $anon = $LASTEXITCODE
    "=== best-validate on the root and the workspace's manifest, signed in, with the registration probe"
    npx -y "@behavioralstate/best-validate@$validate" $base --tenant $ws --api-key $key --auth-type apikey --auth-header X-Api-Key --probe-registration 2>&1 | Select-String -Pattern 'FAIL|WARN|SKIP|CONFORMANT|probe'
    $signed = $LASTEXITCODE
    "=== BEST_PEER_MEMBERS is refused with the fix"
    Start-Door "old" @{ BEST_PEER_MEMBERS = "a=http://127.0.0.1:$($ports.a)" }
    $procs.old.WaitForExit(10000) | Out-Null
    $refused = (Get-Content (Join-Path $dirs.old "err") -Raw -ErrorAction SilentlyContinue)
    $variable = ($procs.old.HasExited -and $procs.old.ExitCode -ne 0 -and $refused -match "configure-cloud")
    if (-not $variable) { "BEST_PEER_MEMBERS was not refused with the fix: $refused" }
    if ($anon -eq 0 -and $signed -eq 0 -and $variable) { "CLOUD VALIDATION GREEN"; exit 0 } else { "CLOUD VALIDATION RED ($anon/$signed/$variable)"; exit 1 }
} finally {
    foreach ($p in $procs.Values) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force; $p.WaitForExit(5000) | Out-Null } }
    Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
}
