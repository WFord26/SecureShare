#Requires -Version 7.2
# Offline tests of Graph PATCH payloads; no deployment or credentials required.
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot '../deploy.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors -join "`n") }
foreach ($name in 'Get-ValidatedBaseUrl', 'Update-EntraAppUrls') {
    $definition = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    . ([scriptblock]::Create($definition.Extent.Text))
}
function Write-Step($Text) {}
function Write-Note($Text) {}
$script:AppId = 'test-client'
$script:AppObjectId = 'test-object'
$script:patches = [Collections.Generic.List[object]]::new()
$script:web = [pscustomobject]@{
    redirectUris = @('https://existing.example/auth/callback')
    homePageUrl = $null
    logoutUrl = 'https://existing.example/logout'
    implicitGrantSettings = @{ enableIdTokenIssuance = $false; enableAccessTokenIssuance = $false }
    redirectUriSettings = @(@{ uri = 'https://existing.example/auth/callback' })
    unexpectedServerMetadata = 'must-not-be-replayed'
}
function Invoke-Graph {
    param($Method = 'GET', $Path, $Body)
    if ($Method -eq 'GET') { return [pscustomobject]@{ web = $script:web } }
    if ($Method -ne 'PATCH') { throw 'Unexpected mutation.' }
    $payload = $Body | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $script:patches.Add($payload)
    # Model documented PATCH semantics: omitted properties stay unchanged.
    foreach ($property in $payload.web.PSObject.Properties) {
        $script:web.($property.Name) = $property.Value
    }
}
Update-EntraAppUrls ' https://share.example/ '
$payload = $script:patches[0]
if (($payload.web.PSObject.Properties.Name | Sort-Object) -join ',' -ne 'homePageUrl,redirectUris') { throw 'PATCH includes unmanaged fields.' }
foreach ($expected in 'https://existing.example/auth/callback', 'https://share.example/auth/callback', 'https://share.example/') {
    if ($expected -cnotin $payload.web.redirectUris) { throw "Missing redirect: $expected" }
}
if ($payload.web.homePageUrl -cne 'https://share.example') { throw 'Incorrect homepage.' }
Update-EntraAppUrls 'https://share.example'
if ($script:patches.Count -ne 1) { throw 'Repeat invocation should not patch.' }
Update-EntraAppUrls 'https://second.example'
if ($script:patches[1].web.PSObject.Properties.Name -contains 'homePageUrl') { throw 'Existing homepage should not be overwritten.' }
foreach ($invalid in '', 'share.example', 'http://share.example', 'https://share.example/#fragment', 'https://share.example/?query=1', 'https://user:pass@share.example', 'https://share.example/bad path') {
    $rejected = $false
    try { Update-EntraAppUrls $invalid } catch { $rejected = $true }
    if (-not $rejected) { throw 'Invalid base URL was accepted.' }
}
Write-Output 'PASS: minimal PATCH fields, preservation of redirects, URL normalization, idempotency, existing homepage and invalid URL rejection.'
