#Requires -Version 7.2
# Exercise the actual Windows batch boundary without contacting Azure.
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if (-not $IsWindows) { Write-Output 'SKIP: Windows batch launcher regression test.'; exit 0 }
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot '../deploy.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors -join "`n") }
# Load only helpers: never execute deployment or read deploy.env.
foreach ($name in 'Invoke-Az', 'Invoke-Graph', 'Format-ODataString', 'Get-GraphFilterPath') {
    $definition = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    . ([scriptblock]::Create($definition.Extent.Text))
}
$testDirectory = Join-Path ([IO.Path]::GetTempPath()) "SecureShare graph test $([guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Path $testDirectory
$launcher = Join-Path $testDirectory 'az.cmd'
$originalPath = $env:PATH
$script:GraphRoot = 'https://graph.microsoft.com/v1.0'
try {
    # Fifth argument is the URL. Echo its enclosing quotes as JSON, exactly as
    # received by cmd.exe. A split at & produces invalid JSON or a nonzero exit.
    [IO.File]::WriteAllText($launcher, "@echo off`r`n@echo %5`r`n")
    $env:PATH = $testDirectory + [IO.Path]::PathSeparator + $originalPath
    $paths = @(
        (Get-GraphFilterPath '/applications' "displayName eq $(Format-ODataString 'SecureShare')" 'id,appId'),
        (Get-GraphFilterPath '/groups' "displayName eq $(Format-ODataString "PAX R&D's Uploaders")" 'id,displayName'),
        '/applications/example?$select=web',
        'https://graph.microsoft.com/v1.0/groups?$select=id&$skiptoken=abc%2Bdef%3D'
    )
    foreach ($path in $paths) {
        $expected = if ($path.StartsWith('https://')) { $path } else { $script:GraphRoot + $path }
        $actual = Invoke-Graph -Path $path
        if ($actual -cne $expected) { throw "Graph URL changed at the batch boundary: $actual" }
    }
    $actual = Invoke-Graph -Method PATCH -Path '/applications/example' -Body @{ displayName = 'SecureShare' }
    if ($actual -cne "$script:GraphRoot/applications/example") { throw 'Body-file request failed.' }
    Write-Output 'PASS: Windows batch URL quoting, encoded filters, group names, select, pagination URLs and body-file requests.'
}
finally {
    $env:PATH = $originalPath
    Remove-Item -LiteralPath $launcher -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $testDirectory -Force -ErrorAction SilentlyContinue
}
