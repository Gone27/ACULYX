$source = "D:\Projects\ACULYX"
$dest = "D:\Projects\ACULYX.zip"
$tempStaging = "$env:TEMP\aculyx-release-staging"

if (Test-Path $tempStaging) {
    Remove-Item -Recurse -Force $tempStaging
}
New-Item -ItemType Directory -Path $tempStaging | Out-Null

# Use robocopy for fast, reliable mirror excluding node_modules, .git, test-results, and zips
robocopy $source $tempStaging /E /XD node_modules .git test-results /XF *.zip | Out-Null

if (Test-Path $dest) {
    Remove-Item -Force $dest
}

Compress-Archive -Path "$tempStaging\*" -DestinationPath $dest -CompressionLevel Optimal -Force

Remove-Item -Recurse -Force $tempStaging

$len = (Get-Item $dest).Length
Write-Host "Successfully packed $dest ($([math]::Round($len / 1MB, 2)) MB)"
