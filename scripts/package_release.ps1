param(
    [Parameter(Mandatory = $true)]
    [string]$Target,
    [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $RootDir "dist"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$versionLine = Select-String -Path (Join-Path $RootDir "Cargo.toml") -Pattern '^version = "(.*)"' | Select-Object -First 1
$version = $versionLine.Matches[0].Groups[1].Value

cargo build --release --target $Target

switch ($Target) {
    "x86_64-pc-windows-msvc" {
        $assetName = "PuppyTerm-windows-x86_64.zip"
        $stageDir = Join-Path $RootDir "target\$Target\package"
        $appRoot = Join-Path $stageDir "PuppyTerm"
        Remove-Item -Recurse -Force $stageDir -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force -Path $appRoot | Out-Null
        Copy-Item (Join-Path $RootDir "target\$Target\release\puppyterm.exe") (Join-Path $appRoot "PuppyTerm.exe")
        New-Item -ItemType Directory -Force -Path (Join-Path $appRoot "assets") | Out-Null
        Copy-Item (Join-Path $RootDir "assets\puppyterm.png") (Join-Path $appRoot "assets\puppyterm.png")
        $output = Join-Path $OutDir $assetName
        Remove-Item $output -ErrorAction SilentlyContinue
        Compress-Archive -Path $appRoot -DestinationPath $output
        Write-Output $output
    }
    default {
        throw "Unsupported target: $Target"
    }
}
