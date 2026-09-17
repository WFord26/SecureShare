#!/usr/bin/env pwsh
#Requires -Version 7.2
<#
.SYNOPSIS
    SecureShare deployment: Entra app registration and enterprise application, infrastructure (Bicep), and the app (zip deploy).

.DESCRIPTION
    Reads infra/deploy.env (the same file deploy.sh uses) and, in order:
      1. Entra (when UPDATE_APP_REG=true): creates or updates the app registration (app roles, sign in permissions,
         client secret) and its enterprise application (assignment required, user and group assignments, admin consent)
      2. Infrastructure: resource providers, resource group, main.bicep
      3. Entra: adds the web app's redirect URIs and home page to the app registration
      4. App: zips the source and pushes it with az webapp deploy; App Service builds it (npm install, npm run build)

    Runs on macOS, Linux and Windows with PowerShell 7.2+ and the Azure CLI. No Python, zip or bash needed.
    Secrets travel through environment variables and temp files, never on a command line.

.PARAMETER InfraOnly
    Entra and Bicep only; no code push.

.PARAMETER AppOnly
    Push the code to an existing deployment only; no Entra or Bicep changes.

.PARAMETER EntraOnly
    App registration and enterprise application only. Use this when the tenant is in another cloud than the
    subscription (Azure China 21Vianet): az cloud set --name AzureChinaCloud; az login; then run with -EntraOnly.

.PARAMETER SkipEntra
    Deploy without touching the app registration or enterprise application, even when UPDATE_APP_REG=true.

.PARAMETER Preview
    Read only: show what the Bicep deployment would change (az deployment group what-if) and exit.

.PARAMETER EnvFile
    Settings file. Default: infra/deploy.env next to this script, or $env:ENV_FILE.

.EXAMPLE
    pwsh infra/deploy.ps1

.EXAMPLE
    pwsh infra/deploy.ps1 -Preview

.EXAMPLE
    pwsh infra/deploy.ps1 -AppOnly
#>
[CmdletBinding(DefaultParameterSetName = 'All')]
param(
    [Parameter(ParameterSetName = 'InfraOnly', Mandatory)][switch]$InfraOnly,
    [Parameter(ParameterSetName = 'AppOnly', Mandatory)][switch]$AppOnly,
    [Parameter(ParameterSetName = 'EntraOnly', Mandatory)][switch]$EntraOnly,
    [Parameter(ParameterSetName = 'Preview', Mandatory)][switch]$Preview,
    [Parameter(ParameterSetName = 'All')]
    [Parameter(ParameterSetName = 'InfraOnly')][switch]$SkipEntra,
    [string]$EnvFile = $(if ($env:ENV_FILE) { $env:ENV_FILE } else { Join-Path $PSScriptRoot 'deploy.env' })
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$Root = Split-Path -Parent $PSScriptRoot
$ParamFile = Join-Path $PSScriptRoot 'main.bicepparam'
$GuidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
$GraphAppId = '00000003-0000-0000-c000-000000000000'
$SignInScopes = @('openid', 'profile', 'email', 'offline_access')   # what MSAL requests at sign in
$UploadRoleValue = 'Files.Upload'
$script:Warnings = [Collections.Generic.List[string]]::new()
$script:LastAzError = ''

# ------------------------------------------------------------------------------------------------ Output

function Write-Step([string]$Text) { Write-Host "== $Text" -ForegroundColor Cyan }
function Write-Note([string]$Text) { Write-Host "   $Text" }
function Add-Warning([string]$Text) {
    $script:Warnings.Add($Text)
    Write-Host "   WARNING: $Text" -ForegroundColor Yellow
}

# ------------------------------------------------------------------------------------------------ deploy.env

function Read-EnvFile([string]$Path) {
    # KEY=value lines, # comments, optional trailing " # comment", optional surrounding quotes
    $values = [ordered]@{}
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ($line -match '^\s*(#|$)') { continue }
        if ($line -notmatch '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$') { continue }
        $key = $Matches[1]
        $value = ($Matches[2] -replace '\s+#.*$', '').Trim()
        if ($value.Length -ge 2 -and ($value[0] -eq '"' -or $value[0] -eq "'") -and $value[-1] -eq $value[0]) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $values[$key] = $value
    }
    $values
}

function Get-Cfg([string]$Key, [string]$Default = '') {
    $value = $script:Cfg[$Key]
    if ([string]::IsNullOrWhiteSpace($value)) { $Default } else { $value }
}

function Test-Cfg([string]$Key) { (Get-Cfg $Key 'false') -eq 'true' }

# Sets a value for this run (and for main.bicepparam, which reads environment variables)
function Set-Cfg([string]$Key, [string]$Value) {
    $script:Cfg[$Key] = $Value
    [Environment]::SetEnvironmentVariable($Key, $Value)
}

# Writes a generated value back to deploy.env so later runs reuse it
function Save-Cfg([string]$Key, [string]$Value) {
    Set-Cfg $Key $Value
    $lines = [Collections.Generic.List[string]]::new([IO.File]::ReadAllLines($EnvFile))
    $pattern = '^\s*' + [regex]::Escape($Key) + '\s*='
    $index = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match $pattern) { $index = $i; break } }
    if ($index -ge 0) { $lines[$index] = "$Key=$Value" } else { $lines.Add("$Key=$Value") }
    [IO.File]::WriteAllText($EnvFile, ($lines -join "`n") + "`n")
    if (-not $IsWindows) { & chmod 600 $EnvFile }
}

# ------------------------------------------------------------------------------------------------ Azure CLI and Graph

# Runs az and returns parsed JSON. Output goes nowhere else, so use Invoke-AzLive for long running commands.
function Invoke-Az {
    param([Parameter(Mandatory)][string[]]$Arguments, [switch]$AllowFailure)
    $script:LastAzError = ''
    $errFile = [IO.Path]::GetTempFileName()
    try {
        $out = & az @Arguments --only-show-errors --output json 2>$errFile
        $code = $LASTEXITCODE
        $err = [IO.File]::ReadAllText($errFile).Trim()
    }
    finally {
        Remove-Item -LiteralPath $errFile -Force -ErrorAction SilentlyContinue
    }
    if ($code -ne 0) {
        $script:LastAzError = $err
        if ($AllowFailure) { return $null }
        throw "az $($Arguments[0..([Math]::Min(2, $Arguments.Count - 1))] -join ' ') failed: $err"
    }
    $text = $out -join "`n"
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $text | ConvertFrom-Json -Depth 64
}

# Runs az with its output shown (progress for deployments)
function Invoke-AzLive([string[]]$Arguments) {
    & az @Arguments
    if ($LASTEXITCODE -ne 0) { throw "az $($Arguments[0..1] -join ' ') failed (exit code $LASTEXITCODE)" }
}

function Invoke-Graph {
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Path, $Body, [switch]$AllowFailure)
    $url = if ($Path.StartsWith('https://')) { $Path } else { $script:GraphRoot + $Path }
    # Windows Azure CLI uses az.cmd. Preserve quotes through PowerShell so
    # cmd.exe does not treat a query-string ampersand as a command separator.
    # Apply only to batch launchers; native executables and Unix need the raw URL.
    $azCommand = Get-Command az -ErrorAction Stop
    if ($IsWindows -and $azCommand.Path -match '\.(cmd|bat)$') {
        $url = '"' + $url.Replace('"', '%22') + '"'
    }
    $arguments = @('rest', '--method', $Method, '--url', $url)
    $bodyFile = $null
    if ($null -ne $Body) {
        $bodyFile = [IO.Path]::GetTempFileName()
        [IO.File]::WriteAllText($bodyFile, ($Body | ConvertTo-Json -Depth 20 -Compress))
        $arguments += @('--headers', 'Content-Type=application/json', '--body', "@$bodyFile")
    }
    try {
        Invoke-Az -Arguments $arguments -AllowFailure:$AllowFailure
    }
    finally {
        if ($bodyFile) { Remove-Item -LiteralPath $bodyFile -Force -ErrorAction SilentlyContinue }
    }
}

# All pages of a Graph collection
function Get-GraphAll([string]$Path) {
    $items = [Collections.Generic.List[object]]::new()
    $next = $Path
    while ($next) {
        $page = Invoke-Graph -Path $next
        foreach ($item in @($page.value)) { if ($null -ne $item) { $items.Add($item) } }
        $next = $page.'@odata.nextLink'
    }
    , $items.ToArray()
}

function Format-ODataString([string]$Value) { "'" + $Value.Replace("'", "''") + "'" }

function Get-GraphFilterPath([string]$Collection, [string]$Filter, [string]$Select) {
    $path = $Collection + '?$filter=' + [uri]::EscapeDataString($Filter)
    if ($Select) { $path += '&$select=' + $Select }
    $path
}

# ------------------------------------------------------------------------------------------------ Entra: app registration and enterprise application

function Initialize-EntraApp {
    $appSelect = 'id,appId,displayName,signInAudience,appRoles,web,requiredResourceAccess,passwordCredentials'
    $tenantId = Get-Cfg 'TENANT_ID'
    $singleTenant = $tenantId -match $GuidPattern
    $clientId = Get-Cfg 'CLIENT_ID'
    if ($clientId -match '^0{8}-0{4}-0{4}-0{4}-0{12}$') { $clientId = '' }

    # ---- App registration
    if ($clientId) {
        Write-Step "App registration $clientId"
        $app = Invoke-Graph -Path "/applications(appId='$clientId')?`$select=$appSelect" -AllowFailure
        if (-not $app) { throw "CLIENT_ID $clientId was not found in tenant $($script:Account.tenantId): $script:LastAzError" }
    }
    else {
        $name = Get-Cfg 'APP_REG_NAME' 'SecureShare'
        Write-Step "App registration '$name'"
        $found = @((Invoke-Graph -Path (Get-GraphFilterPath '/applications' "displayName eq $(Format-ODataString $name)" $appSelect)).value)
        if ($found.Count -gt 1) {
            throw "$($found.Count) app registrations are named '$name'. Set CLIENT_ID in $EnvFile to the one to use."
        }
        if ($found.Count -eq 1) {
            $app = $found[0]
            Write-Note "Using the existing registration (client ID $($app.appId))"
        }
        else {
            $audience = if ($singleTenant) { 'AzureADMyOrg' } else { 'AzureADMultipleOrgs' }
            $created = Invoke-Graph -Method POST -Path '/applications' -Body ([ordered]@{ displayName = $name; signInAudience = $audience })
            $app = Invoke-Graph -Path "/applications/$($created.id)?`$select=$appSelect"
            Write-Note "Created (client ID $($app.appId), $audience)"
        }
        Save-Cfg 'CLIENT_ID' $app.appId
        Write-Note "Saved CLIENT_ID to $EnvFile"
    }
    $script:AppObjectId = $app.id
    $script:AppId = $app.appId

    if ($singleTenant -and $app.signInAudience -ne 'AzureADMyOrg') {
        Write-Note "Sign in audience is $($app.signInAudience); the app still only admits tenant $tenantId"
    }
    if (-not $singleTenant -and $app.signInAudience -eq 'AzureADMyOrg') {
        Add-Warning "TENANT_ID is '$tenantId' but the registration is single tenant, so other tenants cannot sign in. Change 'Supported account types' on the registration."
    }

    # ---- App roles. Graph replaces the whole list, so existing roles are sent back unchanged.
    $auditRole = Get-Cfg 'AUDIT_ROLE' 'Audit.Read'
    $roles = [Collections.Generic.List[object]]::new()
    foreach ($role in @($app.appRoles)) { if ($null -ne $role) { $roles.Add($role) } }
    $wanted = @(
        @{ Value = $UploadRoleValue; Name = 'Uploader'; Description = 'Sign in to SecureShare and create download links' }
        @{ Value = $auditRole; Name = 'Activity log reader'; Description = 'View the SecureShare activity log: every upload, download and revoke' }
    )
    $rolesChanged = $false
    foreach ($w in $wanted) {
        $existing = $roles | Where-Object { $_.value -eq $w.Value } | Select-Object -First 1
        if (-not $existing) {
            $roles.Add([ordered]@{
                    id                 = [guid]::NewGuid().ToString()
                    allowedMemberTypes = @('User')
                    description        = $w.Description
                    displayName        = $w.Name
                    isEnabled          = $true
                    value              = $w.Value
                })
            $rolesChanged = $true
            Write-Note "Adding app role $($w.Value) ($($w.Name))"
        }
        elseif (-not $existing.isEnabled) {
            $existing.isEnabled = $true
            $rolesChanged = $true
            Write-Note "Enabling app role $($w.Value)"
        }
    }
    if ($rolesChanged) {
        Invoke-Graph -Method PATCH -Path "/applications/$($app.id)" -Body @{ appRoles = $roles.ToArray() } | Out-Null
    }
    else {
        Write-Note "App roles present: $UploadRoleValue, $auditRole"
    }
    $script:RoleIds = @{}
    $current = Invoke-Graph -Path "/applications/$($app.id)?`$select=appRoles"
    foreach ($role in @($current.appRoles)) { $script:RoleIds[$role.value] = $role.id }

    # ---- Sign in permissions (Microsoft Graph delegated openid, profile, email, offline_access)
    $graphSp = Invoke-Graph -Path "/servicePrincipals(appId='$GraphAppId')?`$select=id,oauth2PermissionScopes"
    $scopeIds = @{}
    foreach ($s in @($graphSp.oauth2PermissionScopes)) { if ($s.value -in $SignInScopes) { $scopeIds[$s.value] = $s.id } }
    $access = [Collections.Generic.List[object]]::new()
    foreach ($r in @($app.requiredResourceAccess)) { if ($null -ne $r) { $access.Add($r) } }
    $graphEntry = $access | Where-Object { $_.resourceAppId -eq $GraphAppId } | Select-Object -First 1
    $declared = @($graphEntry.resourceAccess | Where-Object { $_.type -eq 'Scope' } | ForEach-Object { $_.id })
    $missing = @($SignInScopes | Where-Object { $scopeIds[$_] -and $scopeIds[$_] -notin $declared })
    if ($missing.Count -gt 0) {
        $entries = [Collections.Generic.List[object]]::new()
        foreach ($ra in @($graphEntry.resourceAccess)) { if ($null -ne $ra) { $entries.Add($ra) } }
        foreach ($m in $missing) { $entries.Add([ordered]@{ id = $scopeIds[$m]; type = 'Scope' }) }
        if ($graphEntry) { $graphEntry.resourceAccess = $entries.ToArray() }
        else { $access.Add([ordered]@{ resourceAppId = $GraphAppId; resourceAccess = $entries.ToArray() }) }
        Invoke-Graph -Method PATCH -Path "/applications/$($app.id)" -Body @{ requiredResourceAccess = $access.ToArray() } | Out-Null
        Write-Note "Declared Microsoft Graph permissions: $($missing -join ', ')"
    }

    # ---- Client secret: create one when CLIENT_SECRET is empty, otherwise check the one in use
    $secret = Get-Cfg 'CLIENT_SECRET'
    if (-not $secret) {
        $months = [int](Get-Cfg 'CLIENT_SECRET_MONTHS' '12')
        $body = @{ passwordCredential = [ordered]@{
                displayName = "secureshare-deploy-$(Get-Date -Format 'yyyyMMdd')"
                endDateTime = [DateTimeOffset]::UtcNow.AddMonths($months).ToString('o')
            }
        }
        $password = Invoke-Graph -Method POST -Path "/applications/$($app.id)/addPassword" -Body $body
        Save-Cfg 'CLIENT_SECRET' $password.secretText
        Write-Note "Created client secret '$($password.displayName)' valid $months months and saved it to $EnvFile"
    }
    else {
        $hint = $secret.Substring(0, [Math]::Min(3, $secret.Length))
        $candidates = @($app.passwordCredentials | Where-Object { $_.hint -eq $hint })
        if ($candidates.Count -eq 0) {
            Add-Warning "CLIENT_SECRET does not match any secret on the registration (compared by its first 3 characters). Sign in will fail with invalid_client. Clear CLIENT_SECRET to have a new one created."
        }
        else {
            $end = ($candidates | ForEach-Object { [DateTimeOffset]$_.endDateTime } | Sort-Object -Descending | Select-Object -First 1)
            $days = [int][Math]::Floor(($end - [DateTimeOffset]::UtcNow).TotalDays)
            if ($days -lt 0) { Add-Warning "The client secret expired on $($end.ToString('yyyy-MM-dd')). Clear CLIENT_SECRET in $EnvFile and run again to create a new one." }
            elseif ($days -le 30) { Add-Warning "The client secret expires in $days days ($($end.ToString('yyyy-MM-dd'))). Clear CLIENT_SECRET in $EnvFile and run again to rotate it." }
            else { Write-Note "Client secret valid until $($end.ToString('yyyy-MM-dd'))" }
        }
    }

    # ---- Enterprise application (service principal)
    Write-Step "Enterprise application"
    $spSelect = 'id,appRoleAssignmentRequired,tags'
    $sp = Invoke-Graph -Path "/servicePrincipals(appId='$($app.appId)')?`$select=$spSelect" -AllowFailure
    if (-not $sp) {
        # A new registration can take a few seconds to replicate
        for ($attempt = 1; -not $sp -and $attempt -le 6; $attempt++) {
            $sp = Invoke-Graph -Method POST -Path '/servicePrincipals' -AllowFailure -Body ([ordered]@{
                    appId = $app.appId
                    tags  = @('WindowsAzureActiveDirectoryIntegratedApp')
                })
            if (-not $sp) {
                if ($script:LastAzError -match 'Authorization_RequestDenied|Insufficient privileges') { break }
                Start-Sleep -Seconds 10
            }
        }
        if (-not $sp) { throw "Could not create the enterprise application: $script:LastAzError" }
        Write-Note "Created"
    }
    elseif ('WindowsAzureActiveDirectoryIntegratedApp' -notin @($sp.tags)) {
        # Without this tag the app is missing from the portal's Enterprise applications list
        $tags = @(@($sp.tags) | Where-Object { $_ }) + 'WindowsAzureActiveDirectoryIntegratedApp'
        Invoke-Graph -Method PATCH -Path "/servicePrincipals/$($sp.id)" -Body @{ tags = $tags } | Out-Null
        Write-Note "Tagged so it is listed under Enterprise applications"
    }
    $script:SpId = $sp.id

    # ---- User and group assignments
    $assignments = [Collections.Generic.List[object]]::new()
    foreach ($a in (Get-GraphAll "/servicePrincipals/$($sp.id)/appRoleAssignedTo?`$top=999")) { $assignments.Add($a) }
    Add-RoleAssignment -RoleValue $UploadRoleValue -List (Get-Cfg 'APP_USERS') -Assignments $assignments
    Add-RoleAssignment -RoleValue $auditRole -List (Get-Cfg 'AUDIT_USERS') -Assignments $assignments
    $uploaders = @($assignments | Where-Object { $_.appRoleId -ne $script:RoleIds[$auditRole] }).Count
    $auditors = @($assignments | Where-Object { $_.appRoleId -eq $script:RoleIds[$auditRole] }).Count
    Write-Note "Assignments: $uploaders with sign in access, $auditors with $auditRole"

    # ---- Assignment required: empty leaves the current setting alone
    $required = Get-Cfg 'ASSIGNMENT_REQUIRED'
    if ($required) {
        $want = $required -eq 'true'
        if ([bool]$sp.appRoleAssignmentRequired -eq $want) {
            Write-Note "Assignment required: $want"
        }
        elseif ($want -and $assignments.Count -eq 0) {
            Add-Warning "Assignment required was NOT turned on: nobody is assigned yet, so nobody could sign in. Set APP_USERS in $EnvFile and run again."
        }
        else {
            Invoke-Graph -Method PATCH -Path "/servicePrincipals/$($sp.id)" -Body @{ appRoleAssignmentRequired = $want } | Out-Null
            if ($want) { Write-Note "Assignment required turned ON: only assigned users and groups can sign in" }
            else { Write-Note "Assignment required turned OFF: every user in the tenant, guests included, can sign in" }
        }
        if ($want -and $uploaders -eq 0 -and $auditors -gt 0) {
            Add-Warning "Only $auditRole holders are assigned. Add the people who upload files to APP_USERS."
        }
    }
    elseif (-not $sp.appRoleAssignmentRequired) {
        Write-Note "Assignment required is off: every user in the tenant can sign in (set ASSIGNMENT_REQUIRED=true to restrict)"
    }

    # ---- Tenant wide admin consent for the sign in permissions
    if (Test-Cfg 'GRANT_ADMIN_CONSENT') {
        $filter = "clientId eq '$($sp.id)' and consentType eq 'AllPrincipals' and resourceId eq '$($graphSp.id)'"
        $grants = @((Invoke-Graph -Path (Get-GraphFilterPath '/oauth2PermissionGrants' $filter)).value)
        $wantedScopes = $SignInScopes -join ' '
        if ($grants.Count -eq 0) {
            $grant = Invoke-Graph -Method POST -Path '/oauth2PermissionGrants' -AllowFailure -Body ([ordered]@{
                    clientId    = $sp.id
                    consentType = 'AllPrincipals'
                    resourceId  = $graphSp.id
                    scope       = $wantedScopes
                })
            if ($grant) { Write-Note "Granted admin consent: $wantedScopes" }
            else { Add-Warning "Could not grant admin consent (needs Cloud Application Administrator or higher). Grant it in the portal: Enterprise applications > the app > Permissions. $script:LastAzError" }
        }
        else {
            $have = @($grants[0].scope -split '\s+' | Where-Object { $_ })
            $add = @($SignInScopes | Where-Object { $_ -notin $have })
            if ($add.Count -gt 0) {
                $patched = Invoke-Graph -Method PATCH -Path "/oauth2PermissionGrants/$($grants[0].id)" -AllowFailure -Body @{ scope = (($have + $add) -join ' ') }
                if ($null -ne $patched -or -not $script:LastAzError) { Write-Note "Admin consent extended with: $($add -join ' ')" }
                else { Add-Warning "Could not extend admin consent: $script:LastAzError" }
            }
            else { Write-Note "Admin consent already granted" }
        }
    }

    if (-not $singleTenant) {
        $authority = (Get-Cfg 'AUTHORITY_HOST' 'https://login.microsoftonline.com').TrimEnd('/')
        foreach ($tid in ((Get-Cfg 'ALLOWED_TENANT_IDS') -split ',' | ForEach-Object Trim | Where-Object { $_ })) {
            if ($tid -ne $script:Account.tenantId) {
                Write-Note "Admin consent link for tenant ${tid}: $authority/$tid/adminconsent?client_id=$($app.appId)"
            }
        }
    }
}

function Resolve-Principal([string]$Who) {
    if ($Who -match $GuidPattern) {
        $obj = Invoke-Graph -Path "/directoryObjects/$Who" -AllowFailure
        if (-not $obj) { return $null }
        return [pscustomobject]@{ Id = $obj.id; Name = $obj.displayName; Type = ($obj.'@odata.type' -replace '^#microsoft\.graph\.', '') }
    }
    if ($Who.Contains('@')) {
        $user = Invoke-Graph -Path ('/users/' + [uri]::EscapeDataString($Who) + '?$select=id,displayName') -AllowFailure
        if (-not $user) {
            # Guests sign in with their own address; their UPN is the #EXT# form
            $found = @((Invoke-Graph -Path (Get-GraphFilterPath '/users' "mail eq $(Format-ODataString $Who)" 'id,displayName')).value)
            if ($found.Count -eq 1) { $user = $found[0] }
        }
        if (-not $user) { return $null }
        return [pscustomobject]@{ Id = $user.id; Name = $Who; Type = 'user' }
    }
    $groups = @((Invoke-Graph -Path (Get-GraphFilterPath '/groups' "displayName eq $(Format-ODataString $Who)" 'id,displayName')).value)
    if ($groups.Count -gt 1) {
        Add-Warning "$($groups.Count) groups are named '$Who'; use the group's object ID instead"
        return $null
    }
    if ($groups.Count -eq 0) { return $null }
    [pscustomobject]@{ Id = $groups[0].id; Name = "group $Who"; Type = 'group' }
}

function Add-RoleAssignment([string]$RoleValue, [string]$List, $Assignments) {
    $roleId = $script:RoleIds[$RoleValue]
    foreach ($who in ($List -split ',' | ForEach-Object Trim | Where-Object { $_ })) {
        $principal = Resolve-Principal $who
        if (-not $principal) { Add-Warning "$who was not found in this tenant; not assigned $RoleValue"; continue }
        if ($principal.Type -notin 'user', 'group') { Add-Warning "$who is a $($principal.Type), not a user or group; skipped"; continue }
        if ($Assignments | Where-Object { $_.principalId -eq $principal.Id -and $_.appRoleId -eq $roleId }) {
            Write-Note "$($principal.Name) already has $RoleValue"
            continue
        }
        $body = [ordered]@{ principalId = $principal.Id; resourceId = $script:SpId; appRoleId = $roleId }
        $result = $null
        # A role added moments ago may not have reached the enterprise application yet
        for ($attempt = 1; -not $result -and $attempt -le 6; $attempt++) {
            $result = Invoke-Graph -Method POST -Path "/servicePrincipals/$($script:SpId)/appRoleAssignedTo" -Body $body -AllowFailure
            if (-not $result) {
                if ($script:LastAzError -notmatch 'not found on application|does not exist') { break }
                Start-Sleep -Seconds 10
            }
        }
        if ($result) {
            $Assignments.Add($result)
            Write-Note "Assigned $RoleValue to $($principal.Name) (takes effect at their next sign in)"
        }
        elseif ($principal.Type -eq 'group' -and $script:LastAzError -match 'license|premium|not supported') {
            Add-Warning "Could not assign $RoleValue to $($principal.Name): group assignment needs Microsoft Entra ID P1 or P2. Assign the users instead."
        }
        else {
            Add-Warning "Could not assign $RoleValue to $($principal.Name): $script:LastAzError"
        }
    }
}

function Get-ValidatedBaseUrl([string]$AppUrl) {
    $AppUrl = $AppUrl.Trim().TrimEnd('/')
    $parsedUrl = $null
    if (-not [uri]::TryCreate($AppUrl, [UriKind]::Absolute, [ref]$parsedUrl) -or
        $parsedUrl.Scheme -ne 'https' -or -not $parsedUrl.Host -or
        $parsedUrl.UserInfo -or $parsedUrl.Query -or $parsedUrl.Fragment -or $AppUrl -match '\s') {
        throw 'The deployment base URL must be an absolute HTTPS URL without credentials, whitespace, a query or a fragment. Check BASE_URL in deploy.env and the deployment baseUrl output.'
    }
    return $AppUrl
}

# Redirect URIs and home page (My Apps tile) once the public URL is known
function Update-EntraAppUrls([string]$AppUrl) {
    $AppUrl = Get-ValidatedBaseUrl $AppUrl
    Write-Step "Redirect URIs on app registration $script:AppId"
    $app = Invoke-Graph -Path "/applications/$($script:AppObjectId)?`$select=web"
    $uris = [Collections.Generic.List[string]]::new()
    foreach ($u in @($app.web.redirectUris)) { if ($u) { $uris.Add($u) } }
    $added = @()
    foreach ($u in @("$AppUrl/auth/callback", "$AppUrl/")) {
        if ($u -notin $uris) { $uris.Add($u); $added += $u }
    }
    # PATCH only the fields we manage. Replaying the GET response can send
    # server metadata or unsupported fields; omitted settings retain their values.
    $web = [ordered]@{}
    if ($added.Count -gt 0) { $web['redirectUris'] = $uris.ToArray() }
    $homeChanged = -not $app.web.homePageUrl
    if ($homeChanged) { $web['homePageUrl'] = $AppUrl }
    if ($added.Count -gt 0 -or $homeChanged) {
        Write-Note "Public URL: $AppUrl"
        Write-Note "Redirect URIs: $AppUrl/auth/callback, $AppUrl/"
        Invoke-Graph -Method PATCH -Path "/applications/$($script:AppObjectId)" -Body @{ web = $web } | Out-Null
    }
    foreach ($u in $added) { Write-Note "Added $u" }
    if ($homeChanged) { Write-Note "Home page set to $AppUrl" }
    if ($added.Count -eq 0) { Write-Note "Already present: $AppUrl/auth/callback, $AppUrl/" }
}

# ------------------------------------------------------------------------------------------------ Deployment outputs

function Get-DeploymentInfo([string]$Name) {
    $outputs = Invoke-Az @('deployment', 'group', 'show', '--name', $Name, '--resource-group', (Get-Cfg 'RG'), '--query', 'properties.outputs')
    [pscustomobject]@{
        WebApp      = $outputs.webAppName.value
        Url         = $outputs.baseUrl.value
        Storage     = $outputs.storageAccountName.value
        PrincipalId = $outputs.principalId.value
    }
}

# Most recent successful deployment, or the names in deploy.env
function Find-ExistingDeployment {
    $rg = Get-Cfg 'RG'
    if (-not $rg) { return $null }
    $query = "[?properties.provisioningState=='Succeeded' && starts_with(name, 'secureshare-')] | sort_by(@, &properties.timestamp) | [-1].name"
    $last = Invoke-Az @('deployment', 'group', 'list', '--resource-group', $rg, '--query', $query) -AllowFailure
    if ($last) {
        $info = Get-DeploymentInfo $last
        if (Get-Cfg 'BASE_URL') { $info.Url = (Get-Cfg 'BASE_URL').TrimEnd('/') }
        return $info
    }
    $webApp = Get-Cfg 'WEB_APP_NAME'
    if (-not $webApp) { return $null }
    $site = Invoke-Az @('webapp', 'show', '--resource-group', $rg, '--name', $webApp, '--query', '{host: defaultHostName, principal: identity.principalId}') -AllowFailure
    if (-not $site) { return $null }
    [pscustomobject]@{
        WebApp      = $webApp
        Url         = (Get-Cfg 'BASE_URL' "https://$($site.host)").TrimEnd('/')
        Storage     = Get-Cfg 'STORAGE_ACCOUNT'
        PrincipalId = $site.principal
    }
}

# ------------------------------------------------------------------------------------------------ App package

function New-AppPackage {
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $zipPath = Join-Path ([IO.Path]::GetTempPath()) "secureshare-$([guid]::NewGuid().ToString('N')).zip"
    $zip = [IO.Compression.ZipFile]::Open($zipPath, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($item in 'package.json', 'package-lock.json', 'tsconfig.json', 'src', 'public') {
            $full = Join-Path $Root $item
            if (Test-Path -LiteralPath $full -PathType Leaf) { $files = @(Get-Item -LiteralPath $full) }
            elseif (Test-Path -LiteralPath $full -PathType Container) { $files = @(Get-ChildItem -LiteralPath $full -File -Recurse -Force) }
            else { throw "Missing $item in $Root" }
            foreach ($file in $files) {
                if ($file.Name -eq '.DS_Store') { continue }
                # Forward slashes: App Service extracts on Linux
                $entry = [IO.Path]::GetRelativePath($Root, $file.FullName).Replace('\', '/')
                [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file.FullName, $entry, [IO.Compression.CompressionLevel]::Optimal)
            }
        }
    }
    finally {
        $zip.Dispose()
    }
    $zipPath
}

# ================================================================================================ Main

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI (az) not found. macOS: brew install azure-cli"
}
if (-not (Test-Path -LiteralPath $EnvFile)) {
    throw "Missing $EnvFile. Copy infra/deploy.env.example to infra/deploy.env and fill it in."
}
$EnvFile = (Resolve-Path -LiteralPath $EnvFile).Path

$script:Cfg = Read-EnvFile $EnvFile
if (Get-Cfg 'BASE_URL') { $script:Cfg['BASE_URL'] = Get-ValidatedBaseUrl (Get-Cfg 'BASE_URL') }
foreach ($key in @($script:Cfg.Keys)) { Set-Cfg $key $script:Cfg[$key] }

$tenantId = Get-Cfg 'TENANT_ID'
if (-not $tenantId -or $tenantId -match '^0{8}-0{4}-0{4}-0{4}-0{12}$') { throw "TENANT_ID is required in $EnvFile" }
if (-not $EntraOnly) {
    foreach ($key in 'RG', 'LOCATION') { if (-not (Get-Cfg $key)) { throw "$key is required in $EnvFile" } }
}

# "az account show" answers from cache even when the refresh token has expired; asking for a token really checks
if (-not (Invoke-Az @('account', 'get-access-token', '--query', 'expiresOn') -AllowFailure)) {
    throw "az CLI is not logged in or the token has expired. Run: az logout; az login"
}
if (-not $EntraOnly -and (Get-Cfg 'SUBSCRIPTION')) {
    Invoke-Az @('account', 'set', '--subscription', (Get-Cfg 'SUBSCRIPTION')) | Out-Null
}
$script:Account = Invoke-Az @('account', 'show')
$cloud = Invoke-Az @('cloud', 'show', '--query', '{name: name, graph: endpoints.microsoftGraphResourceId}')
$script:GraphRoot = $cloud.graph.TrimEnd('/') + '/v1.0'
if ($EntraOnly) { Write-Step "Tenant: $($script:Account.tenantId) ($($cloud.name))" }
else { Write-Step "Subscription: $($script:Account.name) $($script:Account.id) ($($cloud.name))" }

# Entra runs when asked for, and only against the tenant that owns the registration
$runEntra = $EntraOnly -or ((Test-Cfg 'UPDATE_APP_REG') -and -not $SkipEntra -and -not $AppOnly -and -not $Preview)
if ($runEntra -and $tenantId -match $GuidPattern -and $tenantId -ne $script:Account.tenantId) {
    $message = "TENANT_ID $tenantId is not the tenant az is logged into ($($script:Account.tenantId))."
    if ($EntraOnly) { throw "$message Run: az login --tenant $tenantId" }
    Add-Warning "$message Skipping app registration and enterprise application changes; run -EntraOnly after: az login --tenant $tenantId"
    $runEntra = $false
}

# ---- Preview (read only)
if ($Preview) {
    # what-if needs every parameter; placeholders stand in for values the first real run generates
    if (-not (Get-Cfg 'CLIENT_ID')) { Set-Cfg 'CLIENT_ID' '00000000-0000-0000-0000-000000000000' }
    foreach ($key in 'CLIENT_SECRET', 'SESSION_SECRET') { if (-not (Get-Cfg $key)) { Set-Cfg $key 'placeholder-for-what-if-only-00000000' } }
    if (-not (Invoke-Az @('group', 'show', '--name', (Get-Cfg 'RG'), '--query', 'id') -AllowFailure)) {
        throw "Resource group $(Get-Cfg 'RG') does not exist yet; everything in main.bicep would be created."
    }
    Write-Step "What-if for resource group $(Get-Cfg 'RG') (read only, nothing is changed)"
    Invoke-AzLive @('deployment', 'group', 'what-if', '--resource-group', (Get-Cfg 'RG'), '--parameters', $ParamFile)
    exit 0
}

# ---- Session secret: generated once and saved so redeploys do not sign everyone out
if (-not $EntraOnly -and -not (Get-Cfg 'SESSION_SECRET')) {
    Save-Cfg 'SESSION_SECRET' ([Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48)))
    Write-Step "Generated SESSION_SECRET and saved it to $EnvFile"
}

# ---- Entra, part 1
if ($runEntra) {
    Initialize-EntraApp
}
elseif (-not $EntraOnly -and -not $AppOnly) {
    foreach ($key in 'CLIENT_ID', 'CLIENT_SECRET') {
        if (-not (Get-Cfg $key)) { throw "$key is required in $EnvFile (or set UPDATE_APP_REG=true to have this script create it)" }
    }
}

# ---- Infrastructure
$deployment = $null
if (-not $AppOnly -and -not $EntraOnly) {
    Write-Step "Resource providers"
    foreach ($ns in 'Microsoft.Storage', 'Microsoft.Web', 'Microsoft.Security', 'Microsoft.EventGrid') {
        # Microsoft.EventGrid is required by Defender on upload malware scanning, which otherwise silently stays off
        Invoke-AzLive @('provider', 'register', '--namespace', $ns, '--wait', '--output', 'none')
    }

    $rg = Get-Cfg 'RG'
    $existingLocation = Invoke-Az @('group', 'show', '--name', $rg, '--query', 'location') -AllowFailure
    if ($existingLocation) {
        Write-Step "Resource group $rg exists ($existingLocation)"
    }
    else {
        Write-Step "Creating resource group $rg ($(Get-Cfg 'LOCATION'))"
        Invoke-Az @('group', 'create', '--name', $rg, '--location', (Get-Cfg 'LOCATION')) | Out-Null
    }

    $deploymentName = "secureshare-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Write-Step "Deploying infrastructure (Bicep)"
    Invoke-AzLive @('deployment', 'group', 'create', '--name', $deploymentName, '--resource-group', $rg, '--parameters', $ParamFile, '--output', 'none')
    $deployment = Get-DeploymentInfo $deploymentName
}
else {
    # -EntraOnly may be logged into another cloud, so only look the web app up when BASE_URL is not set
    if ($AppOnly -or -not (Get-Cfg 'BASE_URL')) { $deployment = Find-ExistingDeployment }
    if (-not $deployment -and $AppOnly) {
        throw "No successful deployment found in $(Get-Cfg 'RG') and WEB_APP_NAME is not set; run without -AppOnly first."
    }
}

$appUrl = if ($deployment) { $deployment.Url } else { (Get-Cfg 'BASE_URL').TrimEnd('/') }

# ---- Entra, part 2
if ($runEntra) {
    if ($appUrl) { Update-EntraAppUrls $appUrl }
    else { Add-Warning "Public URL unknown (set BASE_URL in $EnvFile); redirect URIs were not added." }
}

# ---- App
if (-not $InfraOnly -and -not $EntraOnly) {
    Write-Step "Packaging app"
    $zipPath = New-AppPackage
    try {
        Write-Step "Deploying app to $($deployment.WebApp) (App Service builds it with npm install + npm run build)"
        Write-Note "The status poll can keep saying 'Starting the site' after the site is already up; Ctrl+C at that point is harmless."
        Invoke-AzLive @('webapp', 'deploy', '--resource-group', (Get-Cfg 'RG'), '--name', $deployment.WebApp, '--src-path', $zipPath,
            '--type', 'zip', '--clean', 'true', '--restart', 'true', '--output', 'none')
    }
    finally {
        Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
    }
}

# ---- Summary
$auditRole = Get-Cfg 'AUDIT_ROLE' 'Audit.Read'
$rgName = Get-Cfg 'RG'
Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
if ($deployment) {
    Write-Host "  Web app:          $($deployment.WebApp)"
    Write-Host "  URL:              $appUrl"
    Write-Host "  Storage account:  $($deployment.Storage)"
    Write-Host "  Managed identity: $($deployment.PrincipalId) (Storage Blob Data Owner and Storage Table Data Contributor)"
    Write-Host "  Activity log:     $appUrl/admin (app role $auditRole)"
}
Write-Host "  App registration: $(Get-Cfg 'CLIENT_ID')"
if ($appUrl -and -not $runEntra) {
    Write-Host ''
    Write-Host "Redirect URIs that must be on the app registration (set UPDATE_APP_REG=true to add them automatically):"
    Write-Host "  $appUrl/auth/callback"
    Write-Host "  $appUrl/"
}
if (-not $EntraOnly -and $deployment) {
    Write-Host ''
    Write-Host 'Next:'
    Write-Host '  1. Wait 2-3 minutes for the first build; watch with:'
    Write-Host "       az webapp log tail --resource-group $rgName --name $($deployment.WebApp)"
    Write-Host "  2. Open $appUrl and follow the README test plan."
    Write-Host '  3. If uploads show "Storage error", every download stays "scanning", or the log says "Activity log check failed",'
    Write-Host '     the role assignments may still be propagating (up to ~5 minutes). Restart the app after that:'
    Write-Host "       az webapp restart --resource-group $rgName --name $($deployment.WebApp)"
}
if ($script:Warnings.Count -gt 0) {
    Write-Host ''
    Write-Host "Warnings ($($script:Warnings.Count)):" -ForegroundColor Yellow
    foreach ($w in $script:Warnings) { Write-Host "  - $w" -ForegroundColor Yellow }
}
