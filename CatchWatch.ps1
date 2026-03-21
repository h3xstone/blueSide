<#
.SYNOPSIS
    Watcher to intercept and save volatile files during malware analysis

.PARAMETER dir
    Folder to monitor.
    E.g.: ".\CatchWatch.ps1 -dir C:\Users\User\AppData\Roaming"
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$dir
)

if (-not $dir) {
    Write-Host "Usage: .\CatchWatch.ps1 -dir <path to monitor>"
    exit
}

if (-not (Test-Path $dir)) {
    Write-Host -ForegroundColor Red "Folder not found: $dir"
    exit
}

# fixed conf
$destPath = "$env:USERPROFILE\Desktop\CatchWatch_Result"
$logFile = Join-Path $destPath "catchwatch.log"

if (-not (Test-Path $destPath)) {
    New-Item -ItemType Directory -Path $destPath | Out-Null
}

Write-Host "[*] Monitoring path: $dir"
Write-Host "[*] Destination folder: $destPath"
Write-Host "[*] Log file: $logFile"
Write-Host "`n(...press CTRL+C to end...)`n"

# list of existing files to ignore
$copiedFiles = @{}
Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue | % { $copiedFiles[$_.FullName.ToLowerInvariant()] = $true }

function AgressiveCopy {
    param ($file)
    
    try {
        $dst = Join-Path $destPath $file.Name
        $c = 1

        # prevents overwriting the same file
        while (Test-Path $dst) {
            $dst = Join-Path $destPath ($file.Name + "_part_$c" + $file.Extension)
            $c ++
        }

        Copy-Item -Path $file.FullName -Destination $dst -Force
        Write-Host -Foreground Green "[+] Copied: $($file.Name)"

        # log
        $logLine = "{0} | {1} | {2} bytes" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $file.FullName, $file.Length
        Add-Content -Path $logFile -Value $logLine
        $copiedFiles[$file.FullName.ToLowerInvariant()] = $true
        }
    catch {}
}

$initialize = $false

while ($true) {
    $files = Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        $key = $f.FullName.ToLowerInvariant()
        if (-not $copiedFiles.ContainsKey($key)) {
            if ($initialized) {
                AgressiveCopy $f
            }
            $copiedFiles[$key] = $true
        }
    }
    $initialized = $true
    Start-Sleep -Milliseconds 50
}
