# SPDX-License-Identifier: AGPL-3.0-or-later

<#
.SYNOPSIS
Install the aqt client (and optionally aqt-server) from a published GitHub release.

.DESCRIPTION
The signed update manifest is the source of truth for what to download: it names the
archive for this platform and carries its sha256, so this script never guesses a
filename or trusts a length. Full signature verification happens on every later
`aqt update`, which checks the manifest against keys compiled into the binary.

.EXAMPLE
iwr -useb https://web.sync.aquitano.me/install.ps1 | iex

.EXAMPLE
& ([scriptblock]::Create((iwr -useb https://web.sync.aquitano.me/install.ps1))) -Server
#>
[CmdletBinding()]
param(
    # Also install aqt-server.
    [switch]$Server,
    # Install location. Defaults to %LOCALAPPDATA%\Programs\aqt.
    [string]$Dir = $(if ($env:AQT_INSTALL_DIR) { $env:AQT_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\aqt' }),
    # Install a specific release tag instead of the latest.
    [string]$Version = $env:AQT_VERSION,
    [string]$Repo = $(if ($env:AQT_REPO) { $env:AQT_REPO } else { 'Aquitano/aqt-sync' })
)

$ErrorActionPreference = 'Stop'
# Invoke-WebRequest's progress bar costs more than the download on Windows PowerShell.
$ProgressPreference = 'SilentlyContinue'

if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'aqt publishes 64-bit builds only; build from source with `make build`.'
}

$arch = 'amd64'
if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
    # No windows/arm64 archive is published yet. Windows runs the amd64 build under
    # emulation, so install it rather than refusing.
    Write-Host 'note: no native arm64 build yet; installing the amd64 build (Windows emulates it).'
}

if ($Version) {
    $base = "https://github.com/$Repo/releases/download/$Version"
} else {
    # GitHub's "latest" is the newest non-prerelease, which is the stable channel.
    $base = "https://github.com/$Repo/releases/latest/download"
}

try {
    $manifest = Invoke-RestMethod -Uri "$base/aqt-update.json" -UseBasicParsing
} catch {
    throw "could not read the release manifest from $base : $_"
}

$artifact = $manifest.artifacts | Where-Object { $_.os -eq 'windows' -and $_.arch -eq $arch } | Select-Object -First 1
if (-not $artifact) {
    throw "the release publishes no archive for windows/$arch"
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("aqt-install-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $archive = Join-Path $tmp $artifact.name
    Write-Host "downloading aqt $($manifest.version) for windows/$arch"
    Invoke-WebRequest -Uri $artifact.url -OutFile $archive -UseBasicParsing

    $size = (Get-Item $archive).Length
    if ($size -ne $artifact.size) {
        throw "size mismatch: got $size bytes, the manifest declares $($artifact.size)"
    }
    $hash = (Get-FileHash -Path $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $artifact.sha256.ToLowerInvariant()) {
        throw "checksum mismatch for $($artifact.name): got $hash, want $($artifact.sha256)"
    }

    Expand-Archive -Path $archive -DestinationPath $tmp -Force
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
    Copy-Item -Path (Join-Path $tmp 'aqt.exe') -Destination (Join-Path $Dir 'aqt.exe') -Force
    Write-Host "installed $(Join-Path $Dir 'aqt.exe')"

    if ($Server) {
        $serverName = $artifact.name -replace '^aqt_', 'aqt-server_'
        $serverUrl = $artifact.url -replace ([regex]::Escape($artifact.name) + '$'), $serverName
        $serverArchive = Join-Path $tmp $serverName
        Invoke-WebRequest -Uri $serverUrl -OutFile $serverArchive -UseBasicParsing
        # The server archive is not described by the client manifest, so its checksum
        # comes from the release's own checksums.txt rather than a signed source. An
        # unreadable or silent checksums.txt is a refusal, not a warning: a check that
        # quietly passes when it cannot run is worse than no check at all.
        try {
            # Derived from the archive's own URL, not $base: the manifest pins an
            # exact tag, so a release published mid-install cannot be consulted here.
            $sumsUrl = ($serverUrl -replace ([regex]::Escape($serverName) + '$'), 'checksums.txt')
            $sums = (Invoke-WebRequest -Uri $sumsUrl -UseBasicParsing).Content
        } catch {
            throw "could not read checksums.txt; refusing to install an unverified $serverName"
        }
        $line = $sums -split "`n" | Where-Object { $_ -match ([regex]::Escape($serverName) + '\s*$') } | Select-Object -First 1
        if (-not $line) { throw "checksums.txt lists no entry for $serverName" }
        $want = ($line -split '\s+')[0].ToLowerInvariant()
        $got = (Get-FileHash -Path $serverArchive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($got -ne $want) { throw "checksum mismatch for ${serverName}: got $got, want $want" }

        Expand-Archive -Path $serverArchive -DestinationPath $tmp -Force
        Copy-Item -Path (Join-Path $tmp 'aqt-server.exe') -Destination (Join-Path $Dir 'aqt-server.exe') -Force
        Write-Host "installed $(Join-Path $Dir 'aqt-server.exe')"
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
# Compare entry by entry rather than as a substring: a directory nested under one
# already on PATH is not itself on PATH. An empty entry means "the current
# directory" to Windows, so an unset user PATH must not gain a leading separator.
$entries = @($userPath -split ';' | Where-Object { $_ })
if (@($entries | ForEach-Object { $_.TrimEnd('\') }) -notcontains $Dir.TrimEnd('\')) {
    [Environment]::SetEnvironmentVariable('Path', (($entries + $Dir) -join ';'), 'User')
    $env:Path = (@($env:Path -split ';' | Where-Object { $_ }) + $Dir) -join ';'
    Write-Host "added $Dir to your user PATH (open a new terminal for it to take effect elsewhere)"
}

Write-Host ''
Write-Host 'next:'
Write-Host '  aqt --server https://your-server signup --email you@example.com   # new account'
Write-Host '  aqt --server https://your-server login --email you@example.com    # account you already have'
Write-Host '  aqt git setup    # only if you want encrypted Git remotes'
