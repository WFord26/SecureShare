# SecureShare

Authenticated file uploads with anonymized public download links.

* Uploaders sign in with Entra ID (OAuth 2.0 / OIDC, auth code flow with PKCE) against a tenant on Azure China (21Vianet)
* Each upload gets an unguessable link anyone can use to download (256 bit random token)
* Links stop working after 7 days and files are deleted by a storage lifecycle policy
* Every file is scanned by Microsoft Defender for Storage on upload; downloads are blocked until the scan finds no threats, and flagged files are deleted

## How each requirement is met

| Requirement | Implementation |
|---|---|
| Upload with auth | Entra ID sign in via MSAL; upload API requires a session |
| Anonymized links | Blob name is a random 256 bit token; the link reveals nothing about the file or uploader |
| Links good for 7 days | App returns 404 once the upload timestamp is older than 7 days |
| Virus scanning | Defender for Storage on upload malware scanning; app reads the scan result blob index tag before serving any download |
| Deletion after 7 days | Blob lifecycle management policy deletes blobs 7 days after creation; the app also deletes eagerly when an expired link is hit |

## Setup

### 1. Azure infrastructure

```bash
cd infra
RG=rg-secureshare LOCATION=westus3 bash setup.sh
```

Creates the resource group, storage account (public access disabled, TLS 1.2 minimum), private container, 7 day lifecycle delete policy, and enables Defender for Storage with on upload malware scanning. Note the storage account name it prints.

Defender for Storage malware scanning is billed per GB scanned (capped at 500 GB/month in the script) plus the per storage account Defender charge.

### 2. Entra ID app registration (Azure China / 21Vianet tenant)

Uploader authentication runs against a separate tenant on Microsoft Azure operated by 21Vianet. National clouds are isolated instances, so the app must be registered inside that tenant through the China portal, and the app talks to the China login endpoint. Set in `.env`:

```
AUTHORITY_HOST=https://login.partner.microsoftonline.cn
TENANT_ID=<the 21Vianet tenant ID>
```

Register the app at [portal.azure.cn](https://portal.azure.cn) (or with az CLI configured for the China cloud):

```bash
az cloud set --name AzureChinaCloud
az login
az ad app create \
  --display-name "SecureShare" \
  --web-redirect-uris "https://YOUR_HOST/auth/callback" "http://localhost:3000/auth/callback" \
  --sign-in-audience AzureADMyOrg
az ad app credential reset --id <appId> --display-name secureshare
az cloud set --name AzureCloud   # switch back for the storage work
```

Put the China tenant ID, app (client) ID, and secret in `.env`. If someone in that tenant other than you performs the registration, they only need to send you those three values plus add your redirect URIs.

Notes on the cross cloud split:

* Identity lives in the 21Vianet tenant; file storage stays in your commercial Azure subscription. The two never talk to each other, so no cross cloud trust is needed.
* Only OIDC/OAuth flows hit the .cn endpoint. Defender scanning, lifecycle deletion, and blob access are unchanged.
* Your app host must be able to reach `login.partner.microsoftonline.cn` outbound over 443.
* For a global tenant instead, set `AUTHORITY_HOST=https://login.microsoftonline.com` and register at portal.azure.com.

### 3. Storage permissions

The app talks to Blob Storage with `DefaultAzureCredential`. Grant your identity (managed identity in production, your `az login` account for local dev) these roles on the storage account:

```bash
az role assignment create --assignee <principalId> \
  --role "Storage Blob Data Contributor" --scope <storageAccountId>
az role assignment create --assignee <principalId> \
  --role "Storage Blob Data Owner" --scope <storageAccountId>
```

Blob Data Owner (or a custom role with tag read permission) is needed to read the Defender scan result blob index tags. Shared key access is disabled on the account, so identity based auth is the only path.

### 4. Run

```bash
cp .env.example .env   # fill in values
npm install
npm run build
npm start              # or: npm run dev
```

## Deployment

Any Node 20+ host works. For Azure App Service:

```bash
az webapp up --name secureshare --resource-group rg-secureshare --runtime "NODE:20-lts"
az webapp identity assign --name secureshare --resource-group rg-secureshare
# then grant that identity the storage roles above and set app settings from .env
```

Set `BASE_URL` to the public HTTPS URL and add it as a redirect URI (`BASE_URL/auth/callback`) on the app registration.

## Security notes

* Container has no public access; all downloads stream through the app so expiry and scan status are enforced on every request
* Expired and nonexistent links return an identical 404, so tokens cannot be probed for existence
* Tokens come from `crypto.randomBytes(32)`: 256 bits, effectively unguessable
* Scan states: pending → 503 with a self refreshing wait page; malicious → 403 and immediate deletion; clean → download
* Uploads are capped (default 100 MB, `MAX_UPLOAD_MB`). Defender on upload scanning currently covers files up to 2 GB
* Session cookies are httpOnly, SameSite Lax, and Secure when served over HTTPS; HSTS is sent on HTTPS deployments
* OAuth flow uses PKCE plus a session bound `state` parameter; post login redirects only accept local paths
* Uploads and downloads are rate limited to bound memory use and abuse
* Logout requires a POST so it cannot be triggered cross site
* Optional hardening: subscribe an Event Grid handler to Defender scan results to quarantine malicious files the moment scanning completes, rather than at first download attempt