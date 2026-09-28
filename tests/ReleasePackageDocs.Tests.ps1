param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $PackageRoot,

    [ValidateNotNullOrEmpty()]
    [string] $SourceRoot = (Split-Path $PSScriptRoot -Parent)
)

$ErrorActionPreference = 'Stop'
$count = 0
function Assert($Value, [string] $Message) {
    if (-not $Value) { throw $Message }
    $script:count++
}

$source = (Resolve-Path -LiteralPath $SourceRoot).Path
$package = (Resolve-Path -LiteralPath $PackageRoot).Path
$sourceDocs = (Resolve-Path -LiteralPath (Join-Path $source 'docs')).Path
$packageDocs = Join-Path $package 'docs'

Assert (Test-Path -LiteralPath (Join-Path $package 'WELA.ps1') -PathType Leaf) 'The package must contain WELA.ps1.'
Assert (Test-Path -LiteralPath $packageDocs -PathType Container) 'The package must contain the docs directory.'

$sourceFiles = @(Get-ChildItem -LiteralPath $sourceDocs -File -Recurse)
Assert ($sourceFiles.Count -gt 0) 'The source docs directory must not be empty.'
foreach ($file in $sourceFiles) {
    $relative = $file.FullName.Substring($sourceDocs.Length).TrimStart([char[]]@(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    ))
    Assert (Test-Path -LiteralPath (Join-Path $packageDocs $relative) -PathType Leaf) "Release package is missing docs/$relative."
}

$entryPoint = Get-Content -LiteralPath (Join-Path $source 'WELA.ps1') -Raw
$helpLinks = @(
    [regex]::Matches($entryPoint, 'docs[/\\][A-Za-z0-9._-]+\.md') |
        ForEach-Object { $_.Value -replace '\\', '/' } |
        Sort-Object -Unique
)
Assert ($helpLinks.Count -gt 0) 'WELA.ps1 must contain at least one documentation link.'
foreach ($link in $helpLinks) {
    $packagePath = Join-Path $package ($link -replace '/', [IO.Path]::DirectorySeparatorChar)
    Assert (Test-Path -LiteralPath $packagePath -PathType Leaf) "CLI help links to a file missing from the release package: $link"
}

Write-Host "PASS: $count release package documentation assertions ($($sourceFiles.Count) docs, $($helpLinks.Count) help links)."
$global:LASTEXITCODE = 0
