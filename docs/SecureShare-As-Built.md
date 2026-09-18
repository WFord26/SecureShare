# SecureShare As-Built

## 1. Purpose

SecureShare provides authenticated file uploads and anonymized public download links. Uploaders authenticate with Microsoft Entra ID. Each file receives a random, time-limited download URL that does not expose the uploader identity or original file name.

## 2. Production architecture

| Component | Implementation | Responsibility |
|---|---|---|
| Web application | Azure Linux App Service running Node.js and Express | Authentication, upload/download APIs, UI, sessions, and audit integration |
| Identity | Microsoft Entra ID OAuth 2.0/OIDC authorization-code flow with PKCE | Sign-in, tenant validation, and application role assignment |
| File storage | Azure StorageV2 Blob container named `uploads` | Private storage for uploaded files |
| Malware scanning | Microsoft Defender for Storage on-upload scanning | Scan verdicts and malware blocking |
| Audit storage | Azure Table Storage tables `uploadlog` and `downloadlog` | Upload, download, revoke, and malware-block records |
| Infrastructure | Bicep in `infra/main.bicep` | Repeatable Azure resource deployment |
| Deployment | `infra/deploy.ps1` or `infra/deploy.sh` | Entra configuration, infrastructure deployment, and application deployment |

The storage account is HTTPS-only, uses TLS 1.2 or later, has public access disabled, and normally has shared-key access disabled. The App Service uses a system-assigned managed identity.

## 3. Access model

The app registration defines these application roles:

- `Files.Upload`: permits sign-in and file upload.
- `Audit.Read` (configured by `AUDIT_ROLE`): permits access to `/admin` and audit exports.

When `ASSIGNMENT_REQUIRED=true`, only users or groups assigned to the enterprise application can sign in. Users assigned only `Files.Upload` can upload but cannot view the audit console. Users assigned `Audit.Read` can view the audit console; the role also permits sign-in when assignment is required.

Role changes take effect at the user's next sign-in. Existing sessions should be signed out and restarted after access changes.

### Entra assignment notes

`APP_USERS` and `AUDIT_USERS` in `infra/deploy.env` accept sign-in names, group display names, or object IDs. Group assignment requires the appropriate Microsoft Entra licensing and permissions. Nested group membership is not included by the deployment script.

Before using a group, verify in the app registration that the relevant app role allows group assignment. The current deployment script creates roles with `allowedMemberTypes` set to `User`; if group assignment fails, update the app role definition through an approved Entra change process before retrying.

## 4. Application behavior

- Upload endpoint: `POST /api/upload`.
- User file list: `GET /api/files`.
- User revocation: `DELETE /api/files/:token`.
- Public download/status URL: `/d/<token>`.
- Health endpoint: `GET /healthz`.
- Admin console: `/admin`.
- Admin report: `GET /api/admin/report`.
- Upload CSV export: `/admin/export/uploads.csv`.
- Download CSV export: `/admin/export/downloads.csv`.

Default operational values are:

- Link lifetime: 7 days (`LINK_TTL_DAYS`).
- Maximum upload size: 100 MB (`MAX_UPLOAD_MB`).
- Concurrent upload limit: 4 (`MAX_CONCURRENT_UPLOADS`).
- Scan policy: `required`.
- Audit retention: 730 days (`AUDIT_RETENTION_DAYS`).
- Storage container: `uploads`.

With `SCAN_POLICY=required`, a download is served only after Defender reports exactly `No threats found`. Pending scans return a temporary status response. Malware, scan errors, unsupported files, and scan-cap conditions fail closed. `best-effort` can allow an unscanned file after `SCAN_GRACE_MINUTES` and requires explicit risk approval.

## 5. Required permissions

The App Service managed identity needs:

- `Storage Blob Data Owner` on the storage account. This is required to read the Defender blob index tags used to determine scan status.
- `Storage Table Data Contributor` on the storage account for the activity log.

If the Blob role is reduced to `Storage Blob Data Contributor`, downloads can remain stuck in scanning because the scan tag cannot be read.

## 6. Deployment

Prerequisites:

- PowerShell 7.2 or later.
- Azure CLI.
- Azure subscription permissions to deploy resources and create role assignments.
- Entra Application Administrator or Cloud Application Administrator permissions when `UPDATE_APP_REG=true`.

Typical deployment:

```powershell
Copy-Item infra/deploy.env.example infra/deploy.env
az login
pwsh infra/check-readiness.ps1
pwsh infra/deploy.ps1 -Preview
pwsh infra/deploy.ps1
```

Useful deployment modes:

| Command | Use |
|---|---|
| `pwsh infra/deploy.ps1 -Preview` | Review the Bicep what-if without changing resources |
| `pwsh infra/deploy.ps1 -InfraOnly` | Configure Entra and deploy infrastructure without pushing application code |
| `pwsh infra/deploy.ps1 -AppOnly` | Push code to an existing deployment |
| `pwsh infra/deploy.ps1 -EntraOnly` | Configure only the app registration and enterprise application |
| `pwsh infra/deploy.ps1 -SkipEntra` | Deploy infrastructure and application without changing Entra |

The script writes generated `CLIENT_ID`, `CLIENT_SECRET`, and `SESSION_SECRET` values back to `infra/deploy.env`. Protect that file and do not commit it.

## 7. Operational constraints

- Sessions and rate-limit state are held in process memory. Operate a single App Service instance unless a shared session store is introduced.
- App Service restarts invalidate active sessions.
- The first App Service build commonly takes two to three minutes.
- Defender scanning is billed by scanned data and requires the `Microsoft.EventGrid` provider.
- Audit logging failures do not stop file transfers, but activity records will be missing until Table Storage access is restored.
- Blob lifecycle management deletes expired blobs after the configured retention period; the application also deletes an expired blob when its link is requested.

## 8. Security and privacy

The audit log contains uploader identity, tenant, IP address, user agent, timestamps, file metadata, scan state, and download outcomes. Retention is configurable and defaults to 730 days. Access to `/admin` must be limited to approved audit administrators, and exported CSV files must be handled as sensitive operational data.
