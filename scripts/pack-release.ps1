Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$sourceDir = "D:\Projects\ACULYX"
$destZip = "D:\Projects\ACULYX.zip"

if (Test-Path $destZip) {
    Remove-Item -Force $destZip
}

# Directories to strictly exclude from release package
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

# File extensions to exclude
$excludeExtensions = @(".zip", ".log")

$files = Get-ChildItem -Path $sourceDir -Recurse -File | Where-Object {
    $rel = $_.FullName.Substring($sourceDir.Length + 1)
    $parts = $rel.Split([System.IO.Path]::DirectorySeparatorChar)

    $excluded = $false
    foreach ($part in $parts) {
        if ($excludeDirs -contains $part) {
            $excluded = $true
            break
        }
    }
    if ($excluded) { return $false }

    if ($excludeExtensions -contains $_.Extension.ToLower()) {
        return $false
    }

    return $true
}

$zip = [System.IO.Compression.ZipFile]::Open($destZip, [System.IO.Compression.ZipArchiveMode]::Create)

try {
    foreach ($file in $files) {
        $relPath = $file.FullName.Substring($sourceDir.Length + 1)
        # RFC 1951 ZIP specification: entry names MUST use forward slashes
        $entryName = $relPath.Replace("\", "/")
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file.FullName, $entryName, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
} finally {
    $zip.Dispose()
}

$len = (Get-Item $destZip).Length
Write-Host "Successfully packed $destZip ($([math]::Round($len / 1MB, 2)) MB, $($files.Count) files)"
