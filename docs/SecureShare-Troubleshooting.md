# SecureShare Troubleshooting Guide

## First checks

1. Confirm the user is using the correct `BASE_URL`.
2. Check application health:

   ```powershell
   Invoke-RestMethod "$env:BASE_URL/healthz"
   ```

3. Tail App Service logs:

   ```powershell
   az webapp log tail --resource-group <resource-group> --name <web-app-name>
   ```

4. Check the deployment readiness report:

   ```powershell
   pwsh infra/check-readiness.ps1 -EnvFile infra/deploy.env
   ```

5. Confirm the latest deployment completed. The first App Service build can take two to three minutes.

## Symptoms and resolutions

| Symptom | Likely cause | Resolution |
|---|---|---|
| `AADSTS50105` at sign-in | Assignment is required and the user or group is not assigned | Assign the user/group to `Files.Upload` or `Audit.Read`, then sign out and sign in again |
| Sign-in succeeds but `/admin` is not authorized | User lacks `Audit.Read` | Add the user to the approved administrator group or assign `Audit.Read` directly |
| Group assignment fails | App role does not allow group members, licensing is missing, or the group is nested | Verify `allowedMemberTypes`, Entra licensing, direct membership, and admin permissions |
| User was added but still lacks access | Existing session has old claims | Sign out fully and start a new sign-in; verify the user is a direct group member |
| Redirect URI error | `BASE_URL/auth/callback` or `BASE_URL/` is missing or differs from the deployed URL | Add the exact HTTPS URLs to the app registration and redeploy/restart if needed |
| Sign-out lands on a Microsoft page | `BASE_URL/` is not registered as a redirect URI | Add the root URL as a web redirect URI |
| Upload fails immediately | Blob access, container name, or App Service configuration is wrong | Check startup logs for `Storage OK`, verify `STORAGE_CONTAINER`, and confirm `Storage Blob Data Owner` |
| Download remains in scan progress | Managed identity cannot read Defender scan tags | Grant `Storage Blob Data Owner`; Blob Data Contributor alone is insufficient |
| File is blocked | Defender found malware or the scan result is not acceptable under `required` policy | Review Defender results; do not manually bypass the required policy for a suspicious file |
| Upload/download works but audit records are missing | Table access is unavailable | Grant `Storage Table Data Contributor` and look for `Activity log OK` or the related startup error |
| Defender scanning is inactive | Event Grid provider is not registered, scanning is not active, or quota/billing is unavailable | Register `Microsoft.EventGrid`, verify Defender for Storage status, and check scan quota and billing |
| App returns 503 during deployment | App Service is still building or restarting | Wait for the build, inspect App Service logs, and retry after deployment completes |
| Sessions disappear after restart | Sessions are held in process memory | Expected behavior; users must sign in again. Use a shared session store before scaling out |
| Multiple instances behave inconsistently | In-memory sessions and rate limits are not shared | Scale back to one instance or implement a shared session store such as Redis |
| Expired link returns not found | Link is older than `LINK_TTL_DAYS` or the blob lifecycle deleted it | Generate a new upload link; this is expected behavior |

## Log messages to recognize

- `Storage OK`: the application can reach the Blob container.
- `Activity log OK`: the application can reach the audit tables.
- Storage failures prevent normal file operations.
- Activity log failures do not stop uploads and downloads, but activity records are not reliable until fixed.

## Deployment recovery

Preview changes before retrying a failed infrastructure deployment:

```powershell
pwsh infra/deploy.ps1 -Preview
```

Then choose the smallest applicable deployment mode:

```powershell
pwsh infra/deploy.ps1 -EntraOnly
pwsh infra/deploy.ps1 -InfraOnly
pwsh infra/deploy.ps1 -AppOnly
```

Use `-SkipEntra` only when the Entra registration and assignments are already correct. Do not delete the storage account to resolve an application or role-assignment issue.

## Escalation data

When escalating, include:

- UTC timestamp and affected URL.
- User's tenant and sign-in name, without sending tokens or secrets.
- Deployment mode and command used.
- App Service name, resource group, and deployment result.
- Relevant log lines, excluding client secrets, session secrets, access tokens, and connection strings.
- Whether the issue affects one user, one group, or all users.
