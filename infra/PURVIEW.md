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
4. File uploads are not a supported DLP action for Entra-registered apps today. Microsoft documents this scope explicitly: "Support today is only available for a DLP policy that blocks prompts based on sensitive information types," using the `UploadText` action ([Entra-registered AI apps: data loss prevention](https://learn.microsoft.com/en-us/purview/ai-entra-registered#data-loss-prevention-and-ai-interactions)). There is no documented `UploadFile` (or equivalent) `RestrictAccess` setting for this app type. Do not create a policy rule using an undocumented setting and assume it covers PDF, Office, archives, images, or encrypted files; the empty `protectionScopes/compute` result for `uploadFile` (`files: "none"`) confirms no applicable policy exists, not a misconfiguration.
5. File content inspection is handled outside the app entirely, at the traffic layer, using Conditional Access App Control. See below.

The policy is a content-inspection pilot, not an anonymous-recipient authorization policy. Production rules must reflect which information uploaders may publish through public links.

## File uploads: Conditional Access App Control (Defender for Cloud Apps)

Purview's `processContent` API has no documented file-upload action for Entra-registered apps (see item 4 above). Rather than build file-text extraction and a second Entra app to route around that gap, file uploads are inspected in-line by Microsoft Defender for Cloud Apps, using the same sensitive-information-type engine as the pilot rule above. This requires no change to SecureShare's code path for enforcement; it is entirely Entra ID and Defender portal configuration.

Prerequisites: Microsoft Entra ID P1 and a Defender for Cloud Apps license (both included in Microsoft 365 E5), and an account with the Conditional Access Administrator role plus Defender for Cloud Apps session policy permissions.

1. **Conditional Access policy** (Entra admin center > Protection > Conditional Access > Policies > New policy):
   - Target resource: the SecureShare app registration (app ID `95e7854e-9206-40eb-b8a1-a9d3583e8141`). Entra ID apps are auto-onboarded to Conditional Access App Control; no manual onboarding step is needed.
   - Users: start scoped to a pilot group, not All users.
   - Session > **Use Conditional Access App Control** > select **Use custom policy** (routes the session through Defender for Cloud Apps).
   - Leave **Enable policy** on **Report-only** until step 3 passes.
2. **Session policy** (Defender portal > Cloud Apps > Policies > Policy management > Create policy > Session policy):
   - Session control type: **Control file upload (with inspection)**.
   - App filter: SecureShare (Automated Azure AD onboarding).
   - Apply to: Data classification services (reuse the Credit Card Number sensitive information type), and optionally Malware detection.
   - Action: **Block**. Do not enable "Always apply the selected action even if the data cannot be scanned" until false-positive behavior on unscannable files (encrypted archives, unsupported types) has been reviewed; that setting fails closed, which is the correct default, but changes what users see.
3. **Test before enforcing.** Move the Conditional Access policy from Report-only to On only after confirming in the Defender portal's Conditional Access App Control traffic log that sign-ins are being routed and inspected.
   - Microsoft Edge sessions use in-browser protection with no reverse proxy. Other browsers are redirected through a reverse proxy (the address bar shows a `*.mcas.ms` suffix). Test both.
   - SecureShare sends a strict CSP (`default-src 'self'; script-src 'self'; ...`, in `src/server.ts`). The reverse-proxy path rewrites the page and may not function correctly under this CSP for non-Edge browsers. Verify the upload page and the `fetch()`-based upload call still work end to end under the proxied session before enforcing; if broken, relax the CSP only as far as required and re-test, rather than removing it.
   - Confirm the actual upload request (not just page navigation) is intercepted and blocked for a synthetic credit-card test file, and that a harmless file still uploads.
4. Session controls apply only to browser-based sessions. A client that calls `/api/upload` directly (bypassing the browser session) is not covered by this control; SecureShare's existing authentication and rate limiting are the relevant controls for that path, not Purview or Defender for Cloud Apps.

Reference: [Conditional Access app control](https://learn.microsoft.com/en-us/defender-cloud-apps/proxy-intro-aad), [Create session policies](https://learn.microsoft.com/en-us/defender-cloud-apps/session-policy-aad).

Review any required Purview pay-as-you-go configuration under [Purview billing](https://learn.microsoft.com/en-us/purview/purview-billing-models); Microsoft 365 E5 alone is not evidence that custom-app API usage is unmetered.

Policy syntax: [New-DlpComplianceRule, Entra application example](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-dlpcompliancerule?view=exchange-ps). Connection: [Security & Compliance PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/connect-to-scc-powershell). Current capability boundary: [Entra application DLP support](https://learn.microsoft.com/en-us/purview/ai-entra-registered#data-loss-prevention-and-ai-interactions).
