# PowerShell wrapper forwarding to canonical cross-platform Node packager (scripts/pack-release.mjs)
param(
    [string]$Target = "all",
    [string]$OutputDir = "",
    [switch]$Overwrite
)

$scriptPath = Join-Path $PSScriptRoot "pack-release.mjs"
$nodeArgs = @($scriptPath, "--target", $Target)

if ($OutputDir) {
    $nodeArgs += @("--output-dir", $OutputDir)
}

if ($Overwrite) {
    $nodeArgs += @("--overwrite")
}

Write-Host "Delegating release packaging to scripts/pack-release.mjs..."
& node @nodeArgs
exit $LASTEXITCODE
