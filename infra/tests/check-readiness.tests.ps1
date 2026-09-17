# Offline contract tests; no Azure CLI, credentials, or modules required.
# Also runnable in Windows PowerShell 5.1 as a compatibility test of the logic.
$ErrorActionPreference = 'Stop'
$source = Get-Content (Join-Path $PSScriptRoot '../check-readiness.ps1') -Raw
$tokens = $null
$parseErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors -join "`n") }
# Run in-process to inspect reports; the production entry point still requires 7.2.
$source = $source -replace '(?m)^#Requires.*$', '' -replace '(?m)^exit \$exitCode\s*$', ''
$check = [scriptblock]::Create($source)
$fixture = [IO.Path]::GetTempFileName()
$script:scenario = ''
$script:calls = [Collections.Generic.List[string]]::new()
function az {
    $script:calls.Add(($args -join ' '))
    $global:LASTEXITCODE = 0
    $command = $args[0..1] -join ' '
    $result = switch ($command) {
        'account show' { @{ id = 'subscription-test'; name = 'Test'; tenantId = '11111111-1111-1111-1111-111111111111'; state = 'Enabled' } }
        'account get-access-token' { 'future-expiry' }
        'cloud show' { @{ name = 'AzureCloud'; endpoints = @{ resourceManager = 'https://management.azure.com/'; activeDirectory = 'https://login.microsoftonline.com/' } } }
        'group exists' { $false }
        'account list-locations' { throw 'Use the subscription-specific REST endpoint for locations.' }
        'provider show' { if ($script:scenario -eq 'provider') { 'NotRegistered' } else { 'Registered' } }
        'rest --method' {
            $url = $args[([array]::IndexOf($args, '--url') + 1)]
            if ($url -like '*/locations?*') {
                if ($url -ne 'https://management.azure.com/subscriptions/subscription-test/locations?api-version=2022-12-01') {
                    throw 'Locations request did not target the configured subscription.'
                }
                if ($script:scenario -eq 'locations-denied') { $global:LASTEXITCODE = 1; return }
                if ($script:scenario -eq 'locations-empty') { @{ value = @() } }
                else { @{ value = @(@{ name = 'westus3' }) } }
                break
            }
            if ($script:scenario -eq 'graph-denied' -and $args -match 'graph.microsoft.com') { $global:LASTEXITCODE = 1; return }
            if ($script:scenario -eq 'no-rbac') { @{ value = @(@{ actions = @('*'); notActions = @('Microsoft.Authorization/*/write') }) } }
            else { @{ value = @(@{ actions = @('*'); notActions = @() }) } }
        }
        'ad app' {
            if ($script:scenario -eq 'graph-denied') { $global:LASTEXITCODE = 1; return }
            @(@{ appId = '22222222-2222-2222-2222-222222222222'; web = @{ redirectUris = @() }; passwordCredentials = @() })
        }
        default { throw "Unexpected or mutating Azure command: $command" }
    }
    ConvertTo-Json -InputObject $result -Depth 10 -Compress
}
function Assert-Check($Report, [string]$Name, [string]$Status) {
    if (-not @($Report.checks | Where-Object { $_.name -eq $Name -and $_.status -eq $Status }).Count) {
        throw "Expected $Status for $Name. Report: $($Report | ConvertTo-Json -Depth 8)"
    }
}
try {
    $settings = @'
SUBSCRIPTION=subscription-test
RG=rg-secureshare
LOCATION=westus3
TENANT_ID=11111111-1111-1111-1111-111111111111
UPDATE_APP_REG=true
CLIENT_ID=22222222-2222-2222-2222-222222222222
CLIENT_SECRET=DO-NOT-PRINT-THIS-SECRET
'@
    [IO.File]::WriteAllText($fixture, $settings)
    $before = Get-Content $fixture -Raw
    $raw = & $check -EnvFile $fixture -Json
    $report = $raw | ConvertFrom-Json
    Assert-Check $report 'Azure session' PASS
    Assert-Check $report 'Region / westus3' PASS
    Assert-Check $report 'Deployment constraints' WARN
    if ($report.exitCode -ne 2) { throw 'Unverified constraints must yield exit code 2.' }
    if ($raw -match 'DO-NOT-PRINT-THIS-SECRET') { throw 'Secret leaked into report.' }
    if ((Get-Content $fixture -Raw) -cne $before) { throw 'Settings were modified.' }

    [IO.File]::WriteAllText($fixture, $settings + "`nBASE_URL=share.paxcenters.com")
    $report = (& $check -EnvFile $fixture -Json) | ConvertFrom-Json
    Assert-Check $report 'Base URL' FAIL
    if ($report.exitCode -ne 1) { throw 'A hostname without HTTPS must fail readiness.' }
    [IO.File]::WriteAllText($fixture, $settings + "`nBASE_URL=https://share.paxcenters.com")
    $report = (& $check -EnvFile $fixture -Json) | ConvertFrom-Json
    Assert-Check $report 'Base URL' PASS
    [IO.File]::WriteAllText($fixture, $settings)

    foreach ($scenario in 'locations-denied', 'locations-empty') {
        $script:scenario = $scenario
        $report = (& $check -EnvFile $fixture -Json) | ConvertFrom-Json
        Assert-Check $report 'Region lookup' WARN
        Assert-Check $report 'Microsoft.EventGrid' PASS
        Assert-Check $report 'App registration' PASS
        if ($report.exitCode -ne 2) { throw 'Unverified region lookup must yield warnings and continue.' }
        if ($scenario -eq 'locations-denied' -and ($report.checks | Where-Object name -eq 'Region lookup').message -notlike '*az rest failed (exit 1)*') {
            throw 'Failed command and exit code were not reported.'
        }
    }

    $script:scenario = 'no-rbac'
    $report = (& $check -EnvFile $fixture -Json) | ConvertFrom-Json
    Assert-Check $report 'Deployment permissions / Microsoft.Authorization/roleAssignments/write' FAIL
    if ($report.exitCode -ne 1) { throw 'Missing RBAC must yield exit code 1.' }

    $script:scenario = 'provider'
    $report = (& $check -EnvFile $fixture -SkipEntra -Json) | ConvertFrom-Json
    Assert-Check $report 'Microsoft.EventGrid' WARN

    $script:scenario = 'graph-denied'
    $script:calls.Clear()
    $report = (& $check -EnvFile $fixture -EntraOnly -Json) | ConvertFrom-Json
    Assert-Check $report 'Graph application access' WARN
    if (@($script:calls | Where-Object { $_ -match '^(provider|group) ' }).Count) { throw 'EntraOnly queried infrastructure.' }

    [IO.File]::WriteAllText($fixture, $settings.Replace('TENANT_ID=11111111-1111-1111-1111-111111111111', 'TENANT_ID=33333333-3333-3333-3333-333333333333'))
    $report = (& $check -EnvFile $fixture -EntraOnly -Json) | ConvertFrom-Json
    Assert-Check $report 'Entra tenant' FAIL

    [IO.File]::WriteAllText($fixture, $settings.Replace('TENANT_ID=11111111-1111-1111-1111-111111111111', "TENANT_ID=organizations`nALLOWED_TENANT_IDS=invalid"))
    $report = (& $check -EnvFile $fixture -EntraOnly -Json) | ConvertFrom-Json
    Assert-Check $report 'Tenant allowlist' FAIL
    Write-Output 'PASS: parser, structured output, secret redaction, read-only settings, subscription-specific regions, region failure isolation, RBAC exclusions, providers, Graph denial, EntraOnly, tenant mismatch, allowlist.'
}
finally { Remove-Item -LiteralPath $fixture -Force }
