# The signed-in lane of scripts/gate.ps1, over https: a fresh data directory, the peer started with an https endpoint
# and no certificate given, so it makes its own; every call pinned to that certificate (curl --cacert, the validator
# through NODE_EXTRA_CA_CERTS); an agent registered through the device flow, admitted with the real
# `best-peer approve` command (the admin token and the door record in the data directory), the credential redeemed,
# then best-validate run with that key and its registration probe. Exit 0 only when the validator says CONFORMANT.
# The same lane as lane_signed_in in scripts/gate.sh.
$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = "$repo\target\release\best-peer.exe"
$validate = (Select-String -Path "$repo\scripts\gate.sh" -Pattern '^BEST_VALIDATE_VERSION=(\S+)' | Select-Object -First 1).Matches[0].Groups[1].Value
if (-not $validate) { throw "scripts/gate.sh names no BEST_VALIDATE_VERSION" }
$data = Join-Path ([System.IO.Path]::GetTempPath()) ("best-peer-validate-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $data | Out-Null
$env:BEST_PEER_DATA = $data
$env:BEST_PEER_LISTEN = "127.0.0.1:7792"
$env:BEST_PEER_ENDPOINT = "https://127.0.0.1:7792"
$env:BEST_PEER_RUNTIME = "fake"
$env:BEST_PEER_GPU = "none"
$cert = Join-Path $data "tls\cert.pem"
$peer = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden
try {
    $base = $env:BEST_PEER_ENDPOINT
    # Git's curl when it is there, otherwise the one on the PATH: --cacert is the only trust it is given, so every
    # call below is pinned to the peer's own file.
    $curl = "$env:ProgramFiles\Git\mingw64\bin\curl.exe"
    if (-not (Test-Path $curl)) { $curl = "curl.exe" }
    $up = $false
    # The process is checked before the port is trusted: a peer left on the port by an earlier run would answer in
    # place of the one that could not bind.
    for ($i = 0; $i -lt 60 -and -not $up -and -not $peer.HasExited; $i++) {
        Start-Sleep -Milliseconds 500
        if (Test-Path $cert) { & $curl -sf --cacert $cert "$base/.well-known/best" 2>&1 | Out-Null; $up = ($LASTEXITCODE -eq 0) }
    }
    if ($peer.HasExited -and -not $up) { "the peer exited before it answered"; exit 1 }
    if (-not $up) { "the peer did not answer over https with the certificate it made"; exit 1 }
    "https: the peer serves with $cert"
    $device = & $curl -sf --cacert $cert -X POST "$base/auth/device" -d client_id=gate -d connection=gate-peer -d "agent_label=the gate" | ConvertFrom-Json
    "device: user_code=$($device.user_code) device_code length=$($device.device_code.Length)"
    if (-not $device.verification_uri.StartsWith("https://")) { "the verification URI is not https"; exit 1 }
    $approve = & $exe approve $device.user_code 2>&1
    "approve: $approve"
    $token = & $curl -sf --cacert $cert -X POST "$base/auth/token" -d grant_type=urn:ietf:params:oauth:grant-type:device_code -d "device_code=$($device.device_code)" -d client_id=gate | ConvertFrom-Json
    "token: name=$($token.name) auth_header=$($token.auth_header) note starts with spec text: $($token.note.StartsWith('The credential is a secret.'))"
    if ($token.name -ne "gate-peer" -or $token.auth_header -ne "X-Api-Key" -or -not $token.note.StartsWith("The credential is a secret.")) { "the token answer lacks a BEST member"; exit 1 }
    $key = $token.access_token
    $hs = & $curl -sf --cacert $cert "$base/queries/get-hardware-state" -H "X-Api-Key: $key" | ConvertFrom-Json
    "hardware: driver=$($hs.driver) devices=$($hs.devices.Count)"
    "=== best-validate, signed in over https, with the registration probe"
    $env:NODE_EXTRA_CA_CERTS = $cert
    npx -y "@behavioralstate/best-validate@$validate" $base --api-key $key --auth-type apikey --auth-header X-Api-Key --probe-registration 2>&1 | Select-String -Pattern 'FAIL|WARN|SKIP|CONFORMANT|probe'
    $code = $LASTEXITCODE
    if ($code -eq 0) { "SIGNED-IN VALIDATION GREEN" } else { "SIGNED-IN VALIDATION RED ($code)" }
    exit $code
} finally {
    if ($peer -and -not $peer.HasExited) { Stop-Process -Id $peer.Id -Force; $peer.WaitForExit(5000) | Out-Null }
    Remove-Item -Recurse -Force $data -ErrorAction SilentlyContinue
}
