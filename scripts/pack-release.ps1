param(
    [string]$Target = "all",
    [string]$OutputDir = "D:/Projects"
)

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$repoRoot = (Resolve-Path "D:/Projects/ACULYX").Path

function Pack-Folder([string]$SourceDir, [string]$DestZip, [string[]]$ExcludeDirs, [string[]]$ExcludeExtensions) {
    if (Test-Path $DestZip) {
        Remove-Item -Force $DestZip
    }

    $files = Get-ChildItem -Path $SourceDir -Recurse -File | Where-Object {
        $rel = $_.FullName.Substring($SourceDir.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
        $parts = $rel.Split(@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar))

        $excluded = $false
        foreach ($part in $parts) {
            if ($ExcludeDirs -contains $part) {
                $excluded = $true
                break
            }
        }
        if ($excluded) { return $false }

        if ($ExcludeExtensions -contains $_.Extension.ToLower()) {
            return $false
        }

        return $true
    }

    $zip = [System.IO.Compression.ZipFile]::Open($DestZip, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in $files) {
            $relPath = $file.FullName.Substring($SourceDir.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
            # RFC 1951 ZIP specification: entry names MUST use forward slashes
            $entryName = $relPath.Replace("\", "/")
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file.FullName, $entryName, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
        }
    } finally {
        $zip.Dispose()
    }

    $len = (Get-Item $DestZip).Length
    Write-Host "Successfully packed $DestZip ($([math]::Round($len / 1MB, 2)) MB, $($files.Count) files)"
}

# 1. Source Archive (Clean source only)
if ($Target -eq "source" -or $Target -eq "all") {
    $sourceZip = Join-Path $OutputDir "ACULYX-source.zip"
    $excludeDirs = @(
        "node_modules",
        ".git",
        ".agents",
        ".system_generated",
        "test-results",
        "playwright-report",
        "coverage",
        ".vite-temp",
        "dist",
        "dist-firefox",
        "dist-hunter"
    )
    $excludeExts = @(".zip", ".log")
    Pack-Folder $repoRoot $sourceZip $excludeDirs $excludeExts
}

# 2. Full Project Archive (Source, tests, docs, plus built dist/, dist-firefox/, dist-hunter/)
if ($Target -eq "full" -or $Target -eq "all") {
    $fullZip = Join-Path $OutputDir "ACULYX-full.zip"
    $excludeDirs = @(
        "node_modules",
        ".git",
        ".agents",
        ".system_generated",
        "test-results",
        "playwright-report",
        "coverage",
        ".vite-temp"
    )
    $excludeExts = @(".zip", ".log")
    Pack-Folder $repoRoot $fullZip $excludeDirs $excludeExts

    # Also sync ACULYX.zip to full archive so extracting ACULYX.zip provides the complete project ready to run
    $legacyZip = Join-Path $OutputDir "ACULYX.zip"
    Copy-Item -Force $fullZip $legacyZip
}

# 2. Chrome Web Store Package (Flat dist/ contents)
if ($Target -eq "chrome" -or $Target -eq "all") {
    $chromeDist = Join-Path $repoRoot "dist"
    if (-not (Test-Path (Join-Path $chromeDist "manifest.json"))) {
        Write-Error "dist/manifest.json not found. Run 'npm run build' before packaging chrome."
        exit 1
    }
    $chromeZip = Join-Path $OutputDir "ACULYX-chrome.zip"
    Pack-Folder $chromeDist $chromeZip @() @(".zip", ".log")
}

# 3. Firefox AMO Package (Flat dist-firefox/ contents)
if ($Target -eq "firefox" -or $Target -eq "all") {
    $firefoxDist = Join-Path $repoRoot "dist-firefox"
    if (-not (Test-Path (Join-Path $firefoxDist "manifest.json"))) {
        Write-Error "dist-firefox/manifest.json not found. Run 'npm run build:firefox' before packaging firefox."
        exit 1
    }
    $firefoxZip = Join-Path $OutputDir "ACULYX-firefox.zip"
    Pack-Folder $firefoxDist $firefoxZip @() @(".zip", ".log")
}
