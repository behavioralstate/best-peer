# Installs the newest release of best-peer on Windows: the archive is taken from GitHub, checked against the release's
# SHA256SUMS, and the binary put, with its LICENSE and README, where a best-peer.exe already is on the PATH, else in
# $env:LOCALAPPDATA\Programs\best-peer, which is added to the user's PATH ($env:BEST_PEER_INSTALL_DIR chooses another
# place over both). Run it again to upgrade: the binary is replaced where it is, the data folder (~\.best-peer: the
# event log, the credentials, the certificate) is not touched, and a peer still running from the folder is named,
# with the command that stops it, not overwritten.
#
#   irm https://raw.githubusercontent.com/behavioralstate/best-peer/main/install.ps1 | iex
#
# $env:BEST_PEER_VERSION = "0.0.12" pins a release instead of the newest.
#
# The whole script is one block: run through `iex` it would otherwise execute in the caller's session, leaving its
# variables and its error preference behind in the window that ran it.
& {
$ErrorActionPreference = "Stop"

$repo = "behavioralstate/best-peer"
$found = (Get-Command best-peer.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if ($env:BEST_PEER_INSTALL_DIR) { $dir = $env:BEST_PEER_INSTALL_DIR; $why = "BEST_PEER_INSTALL_DIR" }
elseif ($found) { $dir = Split-Path -Parent $found; $why = "where best-peer already is, on the PATH" }
else { $dir = Join-Path $env:LOCALAPPDATA "Programs\best-peer"; $why = "the default" }
# A full path, so a relative folder is not written into the PATH and the running-peer check below compares like
# with like.
if (-not [System.IO.Path]::IsPathRooted($dir)) { $dir = Join-Path (Get-Location).Path $dir }
$dir = [System.IO.Path]::GetFullPath($dir)
Write-Host "Installing into $dir ($why)"
# Writable before anything is downloaded: a best-peer.exe that an administrator put on the PATH names a folder this
# user cannot write, and the refusal says what to set rather than failing on the copy.
New-Item -ItemType Directory -Path $dir -Force -ErrorAction SilentlyContinue | Out-Null
try { $probe = Join-Path $dir ([System.IO.Path]::GetRandomFileName()); [System.IO.File]::WriteAllText($probe, ""); Remove-Item $probe -Force }
catch { throw "best-peer: $dir is not writable by you ($why); rerun with `$env:BEST_PEER_INSTALL_DIR = '<a folder you can write>', or from an elevated PowerShell to keep it there" }
$arch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq "Arm64") { "aarch64" } else { "x86_64" }
if ($arch -ne "x86_64") { throw "best-peer: no release for Windows on $arch yet; build it with: cargo install --git https://github.com/$repo best-peer" }
$target = "$arch-pc-windows-msvc"

if ($env:BEST_PEER_VERSION) {
    $base = "https://github.com/$repo/releases/download/v$($env:BEST_PEER_VERSION)"
    $archive = "best-peer-$($env:BEST_PEER_VERSION)-$target.zip"
} else {
    $base = "https://github.com/$repo/releases/latest/download"
    $archive = "best-peer-$target.zip"
}

$exe = Join-Path $dir "best-peer.exe"
$running = Get-Process best-peer -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe }
if ($running) { $ids = $running.Id -join ', '; throw "best-peer: a peer is running from $exe (process $ids); stop it (Stop-Process -Id $ids), then run this again" }

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("best-peer-install-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading $base/$archive"
    try { Invoke-WebRequest -Uri "$base/$archive" -OutFile (Join-Path $tmp $archive) }
    catch { throw "best-peer: $base/$archive could not be downloaded ($($_.Exception.Message)); the releases are at https://github.com/$repo/releases" }
    try { Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile (Join-Path $tmp "SHA256SUMS") }
    catch { throw "best-peer: $base/SHA256SUMS could not be downloaded ($($_.Exception.Message)); the releases are at https://github.com/$repo/releases" }
    $line = Get-Content (Join-Path $tmp "SHA256SUMS") | Where-Object { $_ -match " \*?$([regex]::Escape($archive))$" }
    if (-not $line) { throw "best-peer: $archive is not in SHA256SUMS" }
    $expected = ($line -split "\s+")[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $archive)).Hash.ToLowerInvariant()
    if ($expected -ne $actual) { throw "best-peer: the checksum of $archive does not match SHA256SUMS" }
    Expand-Archive -Path (Join-Path $tmp $archive) -DestinationPath $tmp -Force
    if (-not (Test-Path (Join-Path $tmp "best-peer-$target\best-peer.exe"))) { throw "best-peer: $archive does not hold best-peer-$target\best-peer.exe: a release older than the layout this script knows; pin a newer one" }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    foreach ($file in "best-peer.exe", "LICENSE", "README.md") {
        Copy-Item (Join-Path $tmp "best-peer-$target\$file") (Join-Path $dir $file) -Force
    }
    # The user's PATH is written only when the folder is on no PATH at all: one already reached through the machine's
    # PATH, or this session's, is left as it is.
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (($env:Path -split ";") -notcontains $dir -and ($userPath -split ";") -notcontains $dir) {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$dir", "User")
        $env:Path = "$env:Path;$dir"
        Write-Host "Added $dir to your PATH (open a new terminal for other windows to see it)."
    }
    Write-Host "Installed $(& $exe --version) in $dir"
    Write-Host "Next: best-peer (the README's 'Try it on your machine' says what to set first)"
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
}
