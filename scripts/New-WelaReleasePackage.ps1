[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Destination,

    [ValidateNotNullOrEmpty()]
    [string] $SourceRoot = (Split-Path $PSScriptRoot -Parent)
)

$ErrorActionPreference = 'Stop'
$source = (Resolve-Path -LiteralPath $SourceRoot).Path

if (Test-Path -LiteralPath $Destination) {
    throw "Release package destination already exists: $Destination"
}

$package = (New-Item -ItemType Directory -Path $Destination).FullName
foreach ($relativePath in @('WELA.ps1', 'config', 'scripts', 'modules', 'docs')) {
    $item = Join-Path $source $relativePath
    if (-not (Test-Path -LiteralPath $item)) {
        throw "Required release package input is missing: $item"
    }
    Copy-Item -LiteralPath $item -Destination $package -Recurse -Force
}

Write-Host "Created WELA release package at $package"
