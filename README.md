# SecureShare

Authenticated file uploads with anonymized public download links.

* Uploaders sign in with Entra ID (OAuth 2.0 / OIDC, auth code flow with PKCE). Default is a global / US commercial tenant; Azure China (21Vianet) and US Government tenants are supported by changing one setting
* One command deployment to Azure App Service with Bicep, including the Entra app registration and enterprise application (`infra/deploy.ps1`, PowerShell 7 on macOS, Linux or Windows; `infra/deploy.sh` for bash)
* Each upload gets an unguessable link anyone can use to download (256 bit random token)
* Links stop working after 7 days and files are deleted by a storage lifecycle policy
* Every file is scanned by Microsoft Defender for Storage on upload; by default downloads are blocked until the scan finds no threats, and flagged files are deleted
* Uploaders see their own active links with scan status, expiry and download count, and can revoke a link early
* Activity log: every upload, download, revoke and malware block is recorded for 2 years, with a reporting page and CSV export for people holding an app role

## How each requirement is met

| Requirement | Implementation |
|---|---|
| Upload with auth | Entra ID sign in via MSAL (PKCE + state); upload API requires a session; tenant of every sign in is checked against an allowlist |
| Anonymized links | Blob name is a random 256 bit token; the link reveals nothing about the file or uploader |
| Links good for 7 days | App returns 404 once the upload timestamp is older than `LINK_TTL_DAYS` |
| Virus scanning | Defender for Storage on upload malware scanning; app reads the scan result blob index tag before serving any download |
| Deletion after 7 days | Blob lifecycle management policy deletes blobs 7 days after creation; the app also deletes eagerly when an expired link is hit |
| Upload and download log | Azure Table Storage in the same storage account records who uploaded what and every request for a link; `/admin` reports it (see [Activity log](#activity-log)) |

## Setup

### 1. Azure infrastructure

```bash
cd infra
RG=rg-secureshare LOCATION=westus3 bash setup.sh
```

Creates the resource group, storage account (public access disabled, HTTPS only, TLS 1.2 minimum), private container, 7 day lifecycle delete policy, and enables Defender for Storage with on upload malware scanning. Note the storage account name and resource ID it prints.

Defender for Storage malware scanning is billed per GB scanned (capped at 500 GB/month by default, `SCAN_CAP_GB`) plus the per storage account Defender charge. Enablement can take a few minutes to become active. Malware scanning silently stays off unless the `Microsoft.EventGrid` provider is registered in the subscription (it creates an Event Grid system topic beside the storage account); `setup.sh` and both deploy scripts register it.

### 2. Entra ID app registration

For an App Service deployment, `infra/deploy.ps1` creates and configures the registration, its enterprise application, app roles and assignments for you (see [Enterprise application](#enterprise-application)). The manual steps below are for local development or other hosts.

#### Global / US commercial tenant (default)

Register at [portal.azure.com](https://portal.azure.com) or with the CLI. `BASE_URL/` must be a redirect URI as well as `BASE_URL/auth/callback`, because Entra only honors a post-logout redirect to a registered URI.

```bash
az ad app create \
  --display-name "SecureShare" \
  --web-redirect-uris "https://YOUR_HOST/auth/callback" "https://YOUR_HOST/" "http://localhost:3000/auth/callback" "http://localhost:3000/" \
  --sign-in-audience AzureADMyOrg
az ad app credential reset --id <appId> --display-name secureshare --years 1
```

Set in `.env`:

```
AUTHORITY_HOST=https://login.microsoftonline.com
TENANT_ID=<your tenant ID>
CLIENT_ID=<appId>
CLIENT_SECRET=<password from credential reset>
```

Only users in `TENANT_ID` can sign in. Guests in that tenant sign in through it as well.

#### Several tenants (optional)

To let users from more than one organization upload (an MSP with several client tenants, for example), register the app as multi tenant and list the tenants that are allowed. Every sign in is checked against `ALLOWED_TENANT_IDS`; anyone else gets a 403.

```bash
az ad app create ... --sign-in-audience AzureADMultipleOrgs
```

```
TENANT_ID=organizations
ALLOWED_TENANT_IDS=<tenant A GUID>,<tenant B GUID>
```

An admin in each allowed tenant must consent once (`https://login.microsoftonline.com/<their tenant ID>/adminconsent?client_id=<appId>`), or users consent individually on first sign in if the tenant permits it.

#### Azure China (21Vianet) tenant

National clouds are isolated instances, so the app must be registered inside that tenant through the China portal and the app talks to the China login endpoint. Register at [portal.azure.cn](https://portal.azure.cn) or:

```bash
az cloud set --name AzureChinaCloud
az login
az ad app create ...   # same command as above
az cloud set --name AzureCloud   # switch back for the storage work
```

```
AUTHORITY_HOST=https://login.partner.microsoftonline.cn
TENANT_ID=<the 21Vianet tenant ID>
```

Notes on the cross cloud split:

* Identity lives in the 21Vianet tenant; file storage stays in your commercial Azure subscription. The two never talk to each other, so no cross cloud trust is needed.
* Only OIDC/OAuth flows hit the .cn endpoint. Defender scanning, lifecycle deletion, and blob access are unchanged.
* Your app host must be able to reach `login.partner.microsoftonline.cn` outbound over 443.
* If someone in that tenant other than you performs the registration, they only need to send you the tenant ID, app (client) ID, and secret, plus add your redirect URIs.

| Cloud | `AUTHORITY_HOST` | Portal |
|---|---|---|
| Global / US commercial (default) | `https://login.microsoftonline.com` | portal.azure.com |
| Azure China (21Vianet) | `https://login.partner.microsoftonline.cn` | portal.azure.cn |
| Azure US Government | `https://login.microsoftonline.us` | portal.azure.us |

### 3. Storage permissions

The app talks to Blob Storage with `DefaultAzureCredential`. Grant your identity (managed identity in production, your `az login` account for local dev) this role on the storage account:

```bash
az role assignment create --assignee <principalId> \
  --role "Storage Blob Data Owner" --scope <storageAccountId>
```

For the activity log, also grant Storage Table Data Contributor on the same storage account:

```bash
az role assignment create --assignee <principalId> \
  --role "Storage Table Data Contributor" --scope <storageAccountId>
```

Without it uploads and downloads still work, but nothing is recorded (the app logs this at startup).

Blob Data Owner is required: it includes read/write plus the blob index tag read permission used to check the Defender scan result. With only Blob Data Contributor the app cannot read the tag, treats every file as still scanning, and never serves a download (it logs this at startup and on each download attempt). Alternatively set `STORAGE_CONNECTION_STRING` in `.env` and skip role assignments (less ideal; keys grant full access). Role assignments can take a few minutes to propagate.

### 4. Run

```bash
cp .env.example .env   # fill in values
npm install
npm run build
npm start              # or: npm run dev
```

On startup the app logs whether it can reach the container and which authority it uses.

## Deployment (Azure App Service)

Everything in Azure is defined in [infra/main.bicep](infra/main.bicep): storage account (keys disabled, HTTPS only, TLS 1.2), private container, lifecycle delete policy, Defender for Storage malware scanning, a Linux App Service plan, the web app with a system assigned managed identity, app settings, logging, the activity log tables, and the Storage Blob Data Owner and Storage Table Data Contributor role assignments. This replaces steps 1 and 3 above for a cloud deployment.

### Prerequisites

`infra/deploy.ps1` needs PowerShell 7.2 or later and the Azure CLI. It runs on macOS, Linux and Windows and needs nothing else (no Python, zip or bash). On a Mac:

```bash
brew install --cask powershell
brew install azure-cli
```

The account you sign in with needs Owner on the subscription (or Contributor plus User Access Administrator, for the role assignments) and, for the Entra steps, Cloud Application Administrator or Application Administrator in the tenant.

### Deploy

```bash
cp infra/deploy.env.example infra/deploy.env   # fill in RG, LOCATION, TENANT_ID, APP_USERS, AUDIT_USERS
az login
pwsh infra/deploy.ps1
```

In order, the script:

1. **Entra** (when `UPDATE_APP_REG=true`): finds or creates the app registration, adds the `Files.Upload` and `Audit.Read` app roles and the sign in permissions, creates a client secret if `CLIENT_SECRET` is empty, creates the enterprise application, assigns `APP_USERS` and `AUDIT_USERS`, turns on "Assignment required", and grants admin consent. See [Enterprise application](#enterprise-application)
2. **Infrastructure**: registers the resource providers, creates the resource group, deploys `main.bicep`
3. **Redirect URIs**: adds `BASE_URL/auth/callback` and `BASE_URL/` (and the home page used by the My Apps tile) to the app registration once the web app's URL is known
4. **App**: zips the source and pushes it with `az webapp deploy`; App Service builds it (npm install, npm run build)

Generated values (`CLIENT_ID` for a new registration, `CLIENT_SECRET`, `SESSION_SECRET`) are written back to `deploy.env`, so later deploys reuse them and sessions stay valid. The file is set to mode 600. Secrets travel through environment variables and temp files, never on a command line. Every step is safe to repeat. At the end the script prints the URL, next steps, and any warnings again.

| Switch | Does |
|---|---|
| (none) | Entra, infrastructure and app |
| `-Preview` | Read only what-if of the Bicep deployment; changes nothing |
| `-InfraOnly` | Entra and infrastructure, no code push |
| `-AppOnly` | Code push to an existing deployment only |
| `-EntraOnly` | App registration and enterprise application only |
| `-SkipEntra` | Everything except Entra, even with `UPDATE_APP_REG=true` |
| `-EnvFile <path>` | Use another settings file (default `infra/deploy.env`) |

To adopt resources that already exist (an earlier manual deployment), set their names in `deploy.env`: `WEB_APP_NAME`, `APP_SERVICE_PLAN`, `STORAGE_ACCOUNT`, and `STORAGE_LOCATION` / `APP_LOCATION` if they live in different regions. The template then updates them in place instead of creating new ones. If the web app identity already holds a storage role from a manual setup, set `CREATE_ROLE_ASSIGNMENT=false` or `CREATE_TABLE_ROLE_ASSIGNMENT=false`, because ARM rejects a duplicate assignment. Preview the exact changes first:

```bash
pwsh infra/deploy.ps1 -Preview
```

New App Service apps get a unique default hostname. With `UPDATE_APP_REG=false` the script prints the two redirect URIs to add to the registration yourself. For a custom domain, set `BASE_URL` in `deploy.env` and bind the domain to the web app.

`infra/deploy.sh` is the bash version of the same deployment (`--infra-only`, `--app-only`). It reads the same `deploy.env` but manages less in Entra: it adds redirect URIs, creates the `AUDIT_ROLE` app role and assigns `AUDIT_USERS`. It does not create registrations or secrets, add the `Files.Upload` role, assign `APP_USERS` or groups, set "Assignment required", or grant consent. It needs `CLIENT_ID` and `CLIENT_SECRET` filled in, plus python3 and zip.

### Enterprise application

An Entra app has two halves. The **app registration** holds the redirect URIs, app roles and client secret. The **enterprise application** (service principal) is the tenant's instance of it and controls who may sign in. `deploy.ps1` configures both from `deploy.env`:

| Setting | Effect |
|---|---|
| `UPDATE_APP_REG` | `true` turns all of this on. The CLI must be logged into the tenant that owns the registration; otherwise the script warns and skips it |
| `CLIENT_ID` / `APP_REG_NAME` | Use the registration with this client ID. If empty, use the registration named `APP_REG_NAME` (default `SecureShare`), or create it: single tenant for a tenant GUID, multi tenant for `organizations`. More than one registration with that name is an error |
| `CLIENT_SECRET` / `CLIENT_SECRET_MONTHS` | If empty, a secret valid `CLIENT_SECRET_MONTHS` (default 12) is created. If set, the script checks that it belongs to the registration and warns 30 days before it expires. To rotate, clear it and run again, then delete the old secret in the portal |
| `ASSIGNMENT_REQUIRED` | `true`: only assigned users and groups can sign in; everyone else gets an Entra error before reaching the app. `false`: everyone in the tenant, guests included. Empty: leave the current setting. It is never turned on while nobody is assigned |
| `APP_USERS` | Assigned the `Files.Upload` role (sign in and upload) |
| `AUDIT_USERS` | Assigned the `Audit.Read` role (`AUDIT_ROLE`): the [activity log](#activity-log). With assignment required, this also lets them sign in |
| `GRANT_ADMIN_CONSENT` | `true` grants tenant wide consent for `openid profile email offline_access`, so users see no consent prompt and tenants that block user consent still work |

`APP_USERS` and `AUDIT_USERS` take comma separated sign in names (guests by their own email address), group display names, or object IDs. Groups need Microsoft Entra ID P1 or P2, and members of nested groups are not included. Assignments are only ever added: to remove someone, open Enterprise applications → the app → Users and groups. Roles are read from the ID token, so changes take effect at the next sign in.

The app itself only checks `Audit.Read`. `Files.Upload` exists because once an app defines roles, a user can only be assigned by picking one, so uploaders need a role to be assigned to.

**Multi tenant** (`TENANT_ID=organizations`): the script configures the registration and the enterprise application in your own tenant, and prints an admin consent link for each other tenant in `ALLOWED_TENANT_IDS`. After consenting, each tenant has its own enterprise application where its admins set "Assignment required" and assign their own users and the `Audit.Read` role.

**Azure China (21Vianet) tenant**: storage and App Service live in the commercial cloud and the registration in the China cloud, and one CLI session cannot reach both. Deploy with `UPDATE_APP_REG=false` (or `-SkipEntra`), then configure Entra from a China cloud session. Set `BASE_URL` first so the redirect URIs can be added:

```bash
az cloud set --name AzureChinaCloud
az login --tenant <21Vianet tenant ID>
pwsh infra/deploy.ps1 -EntraOnly
az cloud set --name AzureCloud
```

Doing the same in the portal: Enterprise applications → the app → Properties → Assignment required = Yes; Users and groups → Add user/group → pick a role; Permissions → Grant admin consent.

### Checklist before testing

1. Both `BASE_URL/auth/callback` and `BASE_URL/` are redirect URIs on the app registration
2. First build takes 2-3 minutes; `az webapp log tail` shows it. The startup log lines "Storage OK" and "Activity log OK" confirm the managed identity can reach the container and the tables
3. With "Assignment required" on, you are assigned (in `APP_USERS` or `AUDIT_USERS`), or you will be turned away at sign in
4. Do not set `NODE_ENV=production` as an app setting: App Service builds on the server and that flag makes npm skip devDependencies, so the TypeScript compiler would be missing. The app never renders stack traces regardless
5. Sessions are in process memory: one instance only, and sign ins are lost on restart. Use a session store (Redis) before scaling out
6. Storage account key access is disabled by default (`ALLOW_SHARED_KEY_ACCESS=false`). To browse blobs in the portal, switch the container view to "Microsoft Entra user account" and give yourself Storage Blob Data Reader

Manual alternative without Bicep: [infra/setup.sh](infra/setup.sh) creates only the storage side; then `az webapp up --runtime "NODE:24-lts"`, assign the identity, grant both storage roles, set the app settings listed in the configuration reference, and configure Entra as in setup step 2 and [Enterprise application](#enterprise-application).

### Test plan

1. Open `BASE_URL`, sign in, confirm the "Signed in as" line shows your name and tenant account
2. Upload a small text file, copy the link, open it in a private window: expect the "Scan in progress" page, then the download within a minute or two
3. Upload an [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*` in a .txt): expect "File blocked" and the blob gone from the container
4. Upload a password protected zip: with the default `required` policy expect "File unavailable"; with `SCAN_POLICY=best-effort` it becomes downloadable after the grace period and the uploads list shows "Ready (not scanned)"
5. Sign out: you should land back on `BASE_URL`, not a generic Microsoft page. If you see the generic page, `BASE_URL/` is missing from the redirect URIs
6. Sign in from an account in a tenant that is not allowed: expect "Not authorized"
7. With "Assignment required" on, sign in as a user in your tenant who is not assigned: Entra stops them with error AADSTS50105 before they reach the app
8. Open `BASE_URL/admin` with an account that has the `Audit.Read` role: the uploads from steps 2 to 4 are listed with their download counts, and expanding one shows each request with time, IP address and browser. Without the role expect "Not authorized"

## Activity log

Every upload and every request for a download link is written to two tables in the storage account. The blob lifecycle policy only deletes blobs, so the records stay after the files are gone. The app deletes records older than `AUDIT_RETENTION_DAYS` (default 730, 2 years) once a day.

| Table | One row per | Fields |
|---|---|---|
| `uploadlog` | upload | file name, size, uploader name, email, Entra object ID and tenant, upload IP address, upload time, expiry, final scan result, status (active, expired, revoked, malware blocked), who revoked it and when, download counters, last download |
| `downloadlog` | request for a link | time, file, IP address, user agent, result, bytes sent, duration |

Download results: downloaded, incomplete (cancelled or cut off), link checked (HEAD request), waited for scan, blocked (malware), refused (not scanned), expired link, error. The scan wait page refreshes every 30 seconds; it is recorded once per IP address per 10 minutes.

The link token is never stored. Rows are keyed by a one way hash of it, so neither the tables nor the reporting page can be used to download a file.

**Reporting page.** `BASE_URL/admin` shows totals for a date range, every upload with its download count (click one to see each request for it), all download requests, uploaders, and downloader IP addresses, and exports uploads or downloads as CSV. Uploaders also see a download count under each file on the main page.

**Access.** The page requires the `Audit.Read` app role (`AUDIT_ROLE`). With `UPDATE_APP_REG=true`, `deploy.ps1` and `deploy.sh` create the role on the app registration and assign it to everyone in `AUDIT_USERS`: comma separated sign in names, plus group names in `deploy.ps1` (see [Enterprise application](#enterprise-application)). To do it by hand: app registration → App roles → Create app role (allowed member types: Users/Groups, value `Audit.Read`), then Enterprise applications → the app → Users and groups → Add user/group → pick the role. Groups work too on Entra ID P1 and above. Roles are read from the ID token, so a new assignment takes effect at the next sign in; users with the role see an "Activity log" link on the main page. In multi tenant mode each tenant assigns the role in its own enterprise application.

**What "who downloaded" means.** Download links are anonymous, so a recipient is known only by IP address and browser. Several people behind one office network share an address, and a forwarded link looks like the original recipient on a different IP address. Counts need some care too:

* Link preview and security scanners that fetch links on their own (Teams and Slack previews, Proofpoint, Mimecast, curl and scripts) are recognized by user agent and counted as *automated fetches*, not downloads. Microsoft Defender for Office 365 Safe Links detonation uses an ordinary browser user agent and IP addresses in Microsoft's ranges, so it can show up as a download from a Microsoft IP address
* *Bytes sent* for an incomplete download is what the server wrote to the connection, which can be more than the recipient received
* IP addresses are personal data under GDPR and similar laws. The 2 year retention is enforced automatically; state it in your privacy notice if one applies

For local development the tables are created on startup if they do not exist, using the same credential as blob storage.

## Security notes

* Container has no public access; all downloads stream through the app so expiry and scan status are enforced on every request
* Expired and nonexistent links return an identical 404, so tokens cannot be probed for existence
* Tokens come from `crypto.randomBytes(32)`: 256 bits, effectively unguessable
* Scan states: malicious → 403 and immediate deletion, in every mode. With `SCAN_POLICY=required` (default) nothing is served without an exact "No threats found" verdict: pending → 503 wait page; not scanned, scan error, monthly scan cap reached, or any tag value this code does not recognize → 403. `SCAN_POLICY=best-effort` serves after `SCAN_GRACE_MINUTES` without a verdict and is only for environments where a stranded link is worse than an unscanned download; every such download is logged
* Sign in uses PKCE and a per attempt `state` value. The in flight verifier, state and return path live in a 10 minute HMAC signed cookie, not the session store, so anonymous requests allocate no server state. The session ID is regenerated after login; the `tid` claim is checked against the allowed tenants even in single tenant mode; sign ins without an `oid` claim are rejected
* Cookies are httpOnly, SameSite Lax, Secure over HTTPS, and use the `__Host-` prefix over HTTPS so sibling subdomains cannot plant a cookie of the same name. State changing requests (POST, DELETE) must carry a same origin `Origin` / `Sec-Fetch-Site`, so a sibling subdomain (which is "same site" for SameSite purposes) cannot forge them either
* Rate limits per client IP (the port App Service appends in X-Forwarded-For is stripped, so the limit is per client rather than per connection): `/auth/*` 30 per 10 min, `/api/upload` 40 per 15 min, `/d/*` 60 per min, everything 300 per min. Concurrent uploads are capped by `MAX_CONCURRENT_UPLOADS` because uploads are buffered in memory
* The Entra callback never renders `error_description`: known error codes map to fixed text, so the page cannot be used to put attacker chosen text on this domain. User supplied strings are stripped of control characters before logging
* Every download is logged with a short hash of the token, the client IP and user agent; the token itself never appears in application logs
* Uploads are capped (default 100 MB, `MAX_UPLOAD_MB`). Defender on upload scanning currently covers files up to 2 GB
* HSTS, nosniff, `X-Frame-Options: DENY`, a CSP with `base-uri 'none'` and `object-src 'none'`, `Permissions-Policy`, and `Cache-Control: no-store` are sent on every response
* The uploads list and revoke action are scoped to the signed in user by Entra object ID (email fallback for files uploaded before that was stored); another user's token revoke returns the same 404 as a missing file
* Downloads are always served as `application/octet-stream` with `Content-Disposition: attachment`, so an uploaded HTML file cannot run in the browser on your origin
* Who may sign in is controlled in Entra, not in the app: "Assignment required" on the enterprise application with assigned users or groups (`ASSIGNMENT_REQUIRED=true` and `APP_USERS` in `deploy.env`). Without it every user in the tenant, guests included, can create links
* Recommended in Azure: replace Storage Blob Data Owner with a custom role (Blob Data Contributor + `blobs/tags/read`) scoped to the container, restrict the storage account network to the App Service outbound IPs, enable Defender's "soft delete malicious blobs", send app and storage diagnostics to Log Analytics, and swap the client secret for a federated identity credential on the managed identity
* Optional hardening: subscribe an Event Grid handler to Defender scan results to quarantine malicious files the moment scanning completes, rather than at first download attempt

## Configuration reference

| Variable | Default | Purpose |
|---|---|---|
| `AUTHORITY_HOST` | `https://login.microsoftonline.com` | Entra login endpoint for the cloud the tenant lives in |
| `TENANT_ID` | required | Tenant GUID, or `organizations` for multi tenant |
| `ALLOWED_TENANT_IDS` | empty | Comma separated tenant GUIDs; required with `organizations` |
| `CLIENT_ID`, `CLIENT_SECRET` | required | App registration credentials |
| `BASE_URL` | `http://localhost:3000` | Public URL; builds redirect URI and download links |
| `STORAGE_ACCOUNT`, `STORAGE_CONTAINER` | required, `uploads` | Blob storage location |
| `STORAGE_ENDPOINT_SUFFIX` | `core.windows.net` | Only change if storage is in a national cloud |
| `STORAGE_CONNECTION_STRING` | empty | Key based auth instead of managed identity |
| `SESSION_SECRET` | required | Cookie signing secret, 32+ random characters |
| `PORT` | `3000` | Listen port (App Service sets this) |
| `MAX_UPLOAD_MB` | `100` | Upload size limit |
| `MAX_CONCURRENT_UPLOADS` | `4` | In flight upload cap; worst case memory is this times `MAX_UPLOAD_MB` |
| `LINK_TTL_DAYS` | `7` | Link lifetime; keep in sync with the lifecycle policy `TTL_DAYS` |
| `SCAN_POLICY` | `required` | `required` fails closed; `best-effort` serves after the grace period without a verdict |
| `SCAN_GRACE_MINUTES` | `2` | How long best-effort waits for a Defender verdict before serving |
| `AUDIT_RETENTION_DAYS` | `730` | Days activity log records are kept |
| `AUDIT_ROLE` | `Audit.Read` | App role value that opens the activity log page |
