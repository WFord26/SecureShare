#!/usr/bin/env pwsh
#Requires -Version 7.2
<#
.SYNOPSIS
Read-only preflight for SecureShare's Azure and Entra deployment.
.DESCRIPTION
Reads deploy.env without executing it. Does not log in, switch subscriptions,
register providers, create resources, or read secret values from Azure.
Exit codes: 0 = checks passed, 1 = failures, 2 = warnings / unverified readiness.
This is a pre-deployment check, not an end-to-end application health test.
.PARAMETER EntraOnly
Check identity configuration in the current cloud without checking infrastructure.
.PARAMETER SkipEntra
Check infrastructure only (for separately managed or cross-cloud identity).
.PARAMETER Json
Emit a JSON report instead of human-readable output.
.EXAMPLE
pwsh infra/check-readiness.ps1
.EXAMPLE
pwsh infra/check-readiness.ps1 -SkipEntra -Json
#>
[CmdletBinding(DefaultParameterSetName = 'All')]
param(
    [string]$EnvFile = $(if ($env:ENV_FILE) { $env:ENV_FILE } else { Join-Path $PSScriptRoot 'deploy.env' }),
    [Parameter(ParameterSetName = 'Identity')][switch]$EntraOnly,
    [Parameter(ParameterSetName = 'Infrastructure')][switch]$SkipEntra,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$checks = [Collections.Generic.List[object]]::new()
$cfg = @{}
function Add-Check([string]$Name, [string]$Status, [string]$Message) {
    $checks.Add([pscustomobject]@{ name = $Name; status = $Status; message = $Message })
}
function Get-Cfg([string]$Key, [string]$Default = '') {
    if ([string]::IsNullOrWhiteSpace($cfg[$Key])) { return $Default }
    return $cfg[$Key]
}
function Read-Az([string[]]$Arguments) {
    # Never print native output/errors: they can contain credentials or settings.
    $errFile = [IO.Path]::GetTempFileName()
    try {
        $output = & az @Arguments --only-show-errors --output json 2>$errFile
        if ($LASTEXITCODE -ne 0) {
            $code = $LASTEXITCODE
            # Include command names and recognized error categories, never raw stderr
            # or argument values (which may contain settings or credentials).
            $command = @()
            foreach ($argument in $Arguments) {
                if ($argument.StartsWith('-')) { break }
                $command += $argument
            }
            $errorText = [IO.File]::ReadAllText($errFile)
            $detail = switch -Regex ($errorText) {
                'unrecognized arguments|unrecognized command' { 'CLI command or argument is unsupported.'; break }
                'AuthorizationFailed|Forbidden|Insufficient privileges' { 'Azure denied access to this operation.'; break }
                'AADSTS|az login|expired' { 'Authentication needs attention; sign in again to the intended tenant.'; break }
                'CERTIFICATE_VERIFY_FAILED|certificate verify failed' { 'TLS certificate validation failed; check the CLI trust configuration.'; break }
                'ConnectionError|ProxyError|NameResolutionError|timed out|Failed to resolve' { 'Network or proxy connection failed.'; break }
                default { 'Verify login, access and connectivity; rerun the failed read-only command directly for Azure CLI details.' }
            }
            throw "az $($command -join ' ') failed (exit $code). $detail"
        }
        if ($output) { ($output -join "`n") | ConvertFrom-Json }
    }
    finally { Remove-Item -LiteralPath $errFile -Force -ErrorAction SilentlyContinue }
}
function Read-Pages([string]$Url) {
    do {
        $page = Read-Az @('rest', '--method', 'GET', '--url', $Url)
        foreach ($item in $page.value) { $item }
        $Url = if ($page.nextLink) { $page.nextLink } else { $page.'@odata.nextLink' }
    } while ($Url)
}
function Test-Action($Permissions, [string]$Action) {
    foreach ($permission in $Permissions) {
        $allowed = @($permission.actions | Where-Object { $Action -like $_ }).Count -gt 0
        $excluded = @($permission.notActions | Where-Object { $Action -like $_ }).Count -gt 0
        if ($allowed -and -not $excluded) { return $true }
    }
    return $false
}
function Check-Permissions([string]$Scope, [string[]]$Actions, [string]$Label) {
    try {
        $permissions = @(Read-Pages "$arm$Scope/providers/Microsoft.Authorization/permissions?api-version=2022-04-01")
        foreach ($action in $Actions) {
            if (Test-Action $permissions $action) { Add-Check "$Label / $action" PASS 'Action is present in caller permissions.' }
            else { Add-Check "$Label / $action" FAIL 'Required action missing. Ask an Azure administrator for access at this scope.' }
        }
    }
    catch { Add-Check $Label WARN 'Could not inspect caller permissions. Verify Azure RBAC access manually.' }
}

try {
    if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) { throw 'Settings file missing. Copy infra/deploy.env.example to infra/deploy.env and fill it in.' }
    # Match deploy.ps1 parsing and precedence; do not dot-source the deployment script.
    foreach ($line in [IO.File]::ReadAllLines((Resolve-Path -LiteralPath $EnvFile).Path)) {
        if ($line -notmatch '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$') { continue }
        $key = $Matches[1]
        $value = ($Matches[2] -replace '\s+#.*$', '').Trim()
        if ($value.Length -ge 2 -and ($value[0] -eq '"' -or $value[0] -eq "'") -and $value[-1] -eq $value[0]) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $cfg[$key] = $value
    }
    $configuredUrl = (Get-Cfg 'BASE_URL').Trim().TrimEnd('/')
    if ($configuredUrl) {
        $parsedUrl = $null
        if (-not [uri]::TryCreate($configuredUrl, [UriKind]::Absolute, [ref]$parsedUrl) -or
            $parsedUrl.Scheme -ne 'https' -or -not $parsedUrl.Host -or
            $parsedUrl.UserInfo -or $parsedUrl.Query -or $parsedUrl.Fragment -or $configuredUrl -match '\s') {
            Add-Check 'Base URL' FAIL 'BASE_URL must be a full HTTPS URL, such as https://share.example.com, without credentials, whitespace, a query or a fragment.'
        }
        else { Add-Check 'Base URL' PASS 'An absolute HTTPS base URL is configured.' }
    }
    $tenant = Get-Cfg 'TENANT_ID'
    $id = [guid]::Empty
    if ($tenant -ne 'organizations' -and (-not [guid]::TryParse($tenant, [ref]$id) -or $id -eq [guid]::Empty)) {
        Add-Check 'Tenant configuration' FAIL 'Set TENANT_ID to a tenant GUID or organizations.'
    }
    elseif ($tenant -eq 'organizations') {
        $allowed = @((Get-Cfg 'ALLOWED_TENANT_IDS').Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $invalid = @($allowed | Where-Object { -not [guid]::TryParse($_, [ref]$id) -or $id -eq [guid]::Empty })
        if (-not $allowed.Count -or $invalid.Count) { Add-Check 'Tenant allowlist' FAIL 'Set ALLOWED_TENANT_IDS to comma-separated tenant GUIDs.' }
        else { Add-Check 'Tenant allowlist' PASS 'Multi-tenant allowlist is configured.' }
    }
    else { Add-Check 'Tenant configuration' PASS 'Tenant GUID is configured.' }
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw 'Azure CLI not found. Install it and run az login before checking readiness.' }
    $accountArgs = @('account', 'show')
    if (-not $EntraOnly -and (Get-Cfg 'SUBSCRIPTION')) { $accountArgs += @('--subscription', (Get-Cfg 'SUBSCRIPTION')) }
    $account = Read-Az $accountArgs
    $cloud = Read-Az @('cloud', 'show')
    $arm = $cloud.endpoints.resourceManager.TrimEnd('/')
    $subArgs = @('--subscription', $account.id)
    $null = Read-Az (@('account', 'get-access-token', '--resource', "$arm/", '--query', 'expiresOn') + $subArgs)
    Add-Check 'Azure session' PASS "Authenticated in $($cloud.name); tenant $($account.tenantId)."

    if (-not $EntraOnly) {
        if ($account.state -eq 'Enabled') { Add-Check 'Subscription' PASS "$($account.name) ($($account.id)) is enabled." }
        else { Add-Check 'Subscription' FAIL 'Subscription is not enabled.' }
        $scope = "/subscriptions/$($account.id)"
        $rg = Get-Cfg 'RG'
        $location = Get-Cfg 'LOCATION'
        if (-not $rg -or -not $location) { Add-Check 'Infrastructure configuration' FAIL 'RG and LOCATION are required.' }
        else {
            $exists = Read-Az (@('group', 'exists', '--name', $rg) + $subArgs)
            if ($exists) { Add-Check 'Resource group' PASS 'Target resource group exists.' }
            else { Add-Check 'Resource group' PASS 'Target resource group will be created during deployment.' }
            Check-Permissions $scope @('Microsoft.Resources/subscriptions/resourceGroups/write', 'Microsoft.Resources/subscriptions/providers/register/action') 'Subscription permissions'
            $targetScope = if ($exists) { "$scope/resourceGroups/$rg" } else { $scope }
            $actions = @('Microsoft.Resources/deployments/write', 'Microsoft.Storage/storageAccounts/write', 'Microsoft.Web/serverfarms/write', 'Microsoft.Web/sites/write', 'Microsoft.Security/defenderForStorageSettings/write')
            if ((Get-Cfg 'CREATE_ROLE_ASSIGNMENT' 'true') -eq 'true' -or (Get-Cfg 'CREATE_TABLE_ROLE_ASSIGNMENT' 'true') -eq 'true') {
                $actions += 'Microsoft.Authorization/roleAssignments/write'
            }
            Check-Permissions $targetScope $actions 'Deployment permissions'
            # account list-locations does not accept --subscription in all CLI
            # versions. Address the subscription explicitly without changing defaults.
            $locationsUrl = "$arm$scope/locations?api-version=2022-12-01"
            try {
                $locations = @(Read-Pages $locationsUrl)
                if (-not $locations.Count) { throw 'Azure returned no locations.' }
                foreach ($region in @($location, (Get-Cfg 'APP_LOCATION' $location), (Get-Cfg 'STORAGE_LOCATION' $location)) | Select-Object -Unique) {
                    if ($region -in $locations.name) { Add-Check "Region / $region" PASS 'Region is listed for this subscription.' }
                    else { Add-Check "Region / $region" FAIL 'Region not listed; use an Azure region name such as westus3.' }
                }
            }
            catch {
                Add-Check 'Region lookup' WARN "Could not verify regions. $($_.Exception.Message) Diagnose with: az rest --method GET --url '$locationsUrl' --output table"
            }
        }
        foreach ($provider in 'Microsoft.Storage', 'Microsoft.Web', 'Microsoft.Security', 'Microsoft.EventGrid') {
            try {
                $state = Read-Az (@('provider', 'show', '--namespace', $provider, '--query', 'registrationState') + $subArgs)
                if ($state -eq 'Registered') { Add-Check $provider PASS 'Registered.' }
                else { Add-Check $provider WARN "State: $state. deploy.ps1 registers this provider; registration must finish before use." }
            }
            catch { Add-Check $provider WARN 'Provider registration could not be read.' }
        }
        Add-Check 'Deployment constraints' WARN 'Read-only checks cannot prove quota/capacity, Defender regional availability, Azure Policy, deny assignments or RBAC conditions. Review these and run deploy.ps1 -Preview when the resource group exists.'
    }

    if (-not $SkipEntra) {
        if ($tenant -ne 'organizations' -and $tenant -ne $account.tenantId) {
            Add-Check 'Entra tenant' FAIL 'CLI tenant differs from TENANT_ID. For separate identity, log into that tenant/cloud and run -EntraOnly; run -SkipEntra for infrastructure.'
        }
        else {
            $authority = (Get-Cfg 'AUTHORITY_HOST' 'https://login.microsoftonline.com').TrimEnd('/')
            if ($authority -ne $cloud.endpoints.activeDirectory.TrimEnd('/')) {
                Add-Check 'Authority cloud' FAIL 'AUTHORITY_HOST does not match the active Azure cloud. Select the identity cloud and run -EntraOnly.'
            }
            else { Add-Check 'Authority cloud' PASS 'Authority matches the current cloud.' }
            try {
                $appId = Get-Cfg 'CLIENT_ID'
                if ($appId) { $apps = @(Read-Az @('ad', 'app', 'show', '--id', $appId)) }
                else {
                    $name = (Get-Cfg 'APP_REG_NAME' 'SecureShare').Replace("'", "''")
                    $apps = @(Read-Az @('ad', 'app', 'list', '--filter', "displayName eq '$name'"))
                }
                if ($apps.Count -gt 1) { Add-Check 'App registration' FAIL 'Multiple registrations match APP_REG_NAME. Set CLIENT_ID explicitly.' }
                elseif ($apps.Count -eq 0) {
                    if ((Get-Cfg 'UPDATE_APP_REG' 'false') -eq 'true' -or $EntraOnly) { Add-Check 'App registration' WARN 'Registration does not exist yet; deployment must create it.' }
                    else { Add-Check 'App registration' FAIL 'Registration missing and UPDATE_APP_REG is disabled.' }
                }
                else {
                    $app = $apps[0]
                    Add-Check 'App registration' PASS "Registration found: $($app.appId)."
                    $baseUrl = (Get-Cfg 'BASE_URL').TrimEnd('/')
                    if ($baseUrl) {
                        foreach ($uri in @("$baseUrl/auth/callback", "$baseUrl/")) {
                            if ($uri -in $app.web.redirectUris) { Add-Check 'Redirect URI' PASS $uri }
                            else { Add-Check 'Redirect URI' WARN "Missing $uri; deploy.ps1 can add it when UPDATE_APP_REG=true." }
                        }
                    }
                    else { Add-Check 'Redirect URIs' WARN 'BASE_URL is unknown; verify redirect URIs after deployment.' }
                    $validSecrets = @($app.passwordCredentials | Where-Object { [datetimeoffset]$_.endDateTime -gt [datetimeoffset]::UtcNow.AddDays(30) })
                    if ((Get-Cfg 'CLIENT_SECRET') -and -not $validSecrets.Count) { Add-Check 'Client secret expiry' WARN 'No secret metadata has more than 30 days remaining. Rotate the configured secret.' }
                    elseif (Get-Cfg 'CLIENT_SECRET') { Add-Check 'Client secret' WARN 'Unexpired secret metadata exists, but the configured secret value cannot be verified by a read-only metadata check.' }
                    else { Add-Check 'Client secret' WARN 'CLIENT_SECRET is empty; deployment must generate one with UPDATE_APP_REG=true.' }
                }
            }
            catch { Add-Check 'Graph application access' WARN 'Cannot read the app registration. Verify CLIENT_ID, Graph access and the identity tenant.' }
            if ((Get-Cfg 'UPDATE_APP_REG' 'false') -ne 'true' -and -not $EntraOnly) {
                foreach ($key in 'CLIENT_ID', 'CLIENT_SECRET') {
                    if (-not (Get-Cfg $key)) { Add-Check $key FAIL "$key is required when UPDATE_APP_REG=false." }
                }
            }
            if ((Get-Cfg 'ASSIGNMENT_REQUIRED' 'false') -eq 'true' -and -not (Get-Cfg 'APP_USERS') -and -not (Get-Cfg 'AUDIT_USERS')) {
                Add-Check 'User assignments' WARN 'No APP_USERS or AUDIT_USERS configured. Verify existing assignments or configure an initial user.'
            }
            Add-Check 'Entra write access' WARN 'Read access does not establish permission to create apps, assign users or grant consent. Verify an active Application Administrator / Cloud Application Administrator role (including PIM activation), or equivalent permissions, in the identity tenant.'
        }
    }
    elseif (-not $EntraOnly) {
        foreach ($key in 'CLIENT_ID', 'CLIENT_SECRET') {
            if (-not (Get-Cfg $key)) { Add-Check $key FAIL "$key is required when deploying with -SkipEntra." }
        }
    }
}
catch { Add-Check 'Preflight' FAIL $_.Exception.Message }

$failures = @($checks | Where-Object status -eq 'FAIL').Count
$warnings = @($checks | Where-Object status -eq 'WARN').Count
$exitCode = if ($failures) { 1 } elseif ($warnings) { 2 } else { 0 }
if ($Json) {
    [pscustomobject]@{ checkedAt = [datetimeoffset]::UtcNow.ToString('o'); failures = $failures; warnings = $warnings; exitCode = $exitCode; checks = $checks.ToArray() } | ConvertTo-Json -Depth 8
}
else {
    foreach ($check in $checks) { Write-Host "[$($check.status)] $($check.name): $($check.message)" }
    Write-Host "`n$failures failure(s), $warnings warning(s). Exit code: $exitCode"
}
exit $exitCode
