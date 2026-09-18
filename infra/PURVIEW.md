# Purview Entra setup

Prepare the existing SecureShare registration for delegated Microsoft Graph Purview calls:

```powershell
az login --tenant '<tenant-id>'
pwsh infra/deploy.ps1 -EntraOnly -PurviewPermissions
```

The command reads `infra/deploy.env`. Set `TENANT_ID` and `CLIENT_ID` to the intended tenant and existing SecureShare registration. If `CLIENT_ID` is empty, the existing deploy workflow finds or creates `APP_REG_NAME`. Do not clear an existing client secret merely to add permissions.

The command runs the normal Entra-only setup, including configured roles, user assignments, redirect URIs, and secret creation if the secret is empty. It does not deploy Azure infrastructure or application code.

It adds delegated `Content.Process.User` and `ProtectionScopes.Compute.User`, resolving permission IDs from Microsoft Graph in the target tenant. Existing permissions and consent scopes are preserved. No application permissions or `.All` permissions are added. Missing or disabled permissions stop setup before app changes.

With `GRANT_ADMIN_CONSENT=true`, the script also attempts tenant-wide consent. Review warnings: a successful registration update does not prove consent succeeded. Verify both permissions under Entra > App registrations > SecureShare > API permissions. The signed-in administrator must have permission to update the registration and grant the requested consent.

This prepares identity only. SecureShare does not yet request these Graph scopes, call Purview, or block sensitive content. A separate application-scoped Purview DLP policy and validation of file enforcement/API billing are required. Adding permissions does not extend existing SharePoint/Endpoint DLP rules to this app. Future delegated integration must acquire a Graph access token for the signed-in uploader; the existing ID token cannot be used to call Graph.

References: [Purview integration](https://learn.microsoft.com/en-us/purview/developer/use-the-api), [Process content permissions](https://learn.microsoft.com/en-us/graph/api/userdatasecurityandgovernance-processcontent?view=graph-rest-1.0).

## Create the first application policy

Run these commands in an interactive PowerShell session with an administrator who can manage Purview DLP policies. Sign in to tenant `9c57873b-e249-4b43-a51e-dbc5b920310b`. Entra application consent and Purview policy administration are separate permissions.

Install the module once if it is not already installed, then connect:

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Import-Module ExchangeOnlineManagement
Connect-IPPSSession -UserPrincipalName '<your-admin-UPN>'
```

This initial proof of concept uses the built-in Credit Card Number sensitive information type and the documented `UploadText` blocking action. It is scoped to the SecureShare application and all users within that application. It does not change SharePoint, Exchange, or endpoint policies. It is not proof that raw file uploads are inspected. SecureShare currently does not call this API, so creating the policy alone does not block its uploads or downloads.

Execute the following as one block. A pre-existing policy or rule causes a stop so it can be reviewed instead of overwritten. The policy is created disabled, the rule is added, and only then is the policy enabled. If creation fails midway, inspect the named policy and rule before retrying; do not delete another policy to resolve a name collision.

```powershell
$ErrorActionPreference = 'Stop'
$policyName = 'SecureShare - Purview API pilot'
$ruleName = 'SecureShare - Block credit card text'
$appId = '95e7854e-9206-40eb-b8a1-a9d3583e8141'

$existingPolicies = @(Get-DlpCompliancePolicy)
$existingRules = @(Get-DlpComplianceRule)
if ($policyName -in $existingPolicies.Name -or $ruleName -in $existingRules.Name) {
    throw 'Pilot policy or rule already exists. Inspect it before making further changes.'
}
$sit = Get-DlpSensitiveInformationType -Identity 'Credit Card Number'
if (-not $sit) { throw 'Credit Card Number sensitive information type was not found.' }

$locations = ConvertTo-Json -Depth 6 -Compress -InputObject @(
    @{
        Workload = 'Applications'
        Location = $appId
        LocationDisplayName = 'SecureShare'
        LocationSource = 'Entra'
        LocationType = 'Individual'
        Inclusions = @(@{ Type = 'Tenant'; Identity = 'All' })
    }
)

New-DlpCompliancePolicy -Name $policyName -Mode Disable `
    -Locations $locations -EnforcementPlanes @('Application')

New-DlpComplianceRule -Name $ruleName -Policy $policyName `
    -ContentContainsSensitiveInformation @{ Name = 'Credit Card Number' } `
    -RestrictAccess @(@{ setting = 'UploadText'; value = 'Block' })

Set-DlpCompliancePolicy -Identity $policyName -Mode Enable

Get-DlpCompliancePolicy -Identity $policyName -DistributionDetail |
    Format-List Name,Mode,Enabled,DistributionStatus,DistributionResults,Locations,EnforcementPlanes
Get-DlpComplianceRule -Identity $ruleName |
    Format-List Name,Disabled,ContentContainsSensitiveInformation,RestrictAccess
```

Allow policy propagation and inspect distribution results. If commands or parameters are missing, check the connected tenant, DLP administration role, and module/service availability. Do not replace the application scope with a broad Microsoft 365 location to work around an error.

To disable this pilot:

```powershell
Set-DlpCompliancePolicy -Identity 'SecureShare - Purview API pilot' -Mode Disable
```

## Validate the policy before implementing file release

The next integration test needs a Graph access token issued to SecureShare for a licensed test uploader, with the two delegated Purview scopes. An Azure CLI token or an ID token is not a substitute for that application token.

1. Call `/me/dataSecurityAndGovernance/protectionScopes/compute` with activity `uploadText` and a `policyLocationApplication` whose value is the SecureShare app ID above. Expect an applicable scope with `evaluateInline`. Empty scopes or only `evaluateOffline` do not prove blocking is configured.
2. Submit synthetic credit-card test text (including contextual words, with no real cardholder data) through `/me/dataSecurityAndGovernance/processContent`, using SecureShare as the protected application and the policy ETag as `If-None-Match`. Expect `restrictAccess` with `restrictionAction: block`, and no processing errors.
3. Test harmless text as a negative control. HTTP success by itself is not policy approval; inspect the returned actions and processing errors.
4. Separately establish support for the required file types and `uploadFile` policies. The API documents file metadata, but the application DLP guidance documents text blocking. Do not silently substitute `UploadFile` in this rule or assume it covers PDF, Office, archives, images, or encrypted files.
5. If evaluating extracted file text is the supported route, implement and test complete extraction/OCR and file-size handling. Keep files blocked when extraction or evaluation is incomplete. A text verdict must be tied to the exact original blob content before release.

The policy is a content-inspection pilot, not an anonymous-recipient authorization policy. Production rules must reflect which information uploaders may publish through public links.

Review any required Purview pay-as-you-go configuration under [Purview billing](https://learn.microsoft.com/en-us/purview/purview-billing-models); Microsoft 365 E5 alone is not evidence that custom-app API usage is unmetered.

Policy syntax: [New-DlpComplianceRule, Entra application example](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-dlpcompliancerule?view=exchange-ps). Connection: [Security & Compliance PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/connect-to-scc-powershell). Current capability boundary: [Entra application DLP support](https://learn.microsoft.com/en-us/purview/ai-entra-registered#data-loss-prevention-and-ai-interactions).
