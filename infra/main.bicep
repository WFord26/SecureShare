// SecureShare: storage + Defender malware scanning + Linux App Service with managed identity.
// Deploy with infra/deploy.sh (reads infra/deploy.env) or:
//   az deployment group create -g <rg> --parameters infra/main.bicepparam
targetScope = 'resourceGroup'

@description('Base name used to derive resource names (lowercase letters, digits, hyphens).')
@minLength(3)
@maxLength(24)
param baseName string = 'secureshare'

@description('Default Azure region.')
param location string = resourceGroup().location

@description('Region for the storage account. Empty = location.')
param storageLocation string = ''

@description('Region for the App Service plan and web app. Empty = location.')
param appLocation string = ''

@description('App Service plan name override. Empty = asp-<baseName>.')
param planName string = ''

@description('App Service plan SKU. B1 is enough for testing.')
@allowed(['F1', 'B1', 'B2', 'B3', 'S1', 'P0v3', 'P1v3'])
param appServiceSku string = 'B1'

@description('Node.js runtime on Linux App Service.')
param nodeVersion string = '24-lts'

@description('Entra authority host. Global: https://login.microsoftonline.com, Azure China: https://login.partner.microsoftonline.cn, US Gov: https://login.microsoftonline.us')
#disable-next-line no-hardcoded-env-urls
param authorityHost string = 'https://login.microsoftonline.com'

@description('Tenant ID GUID for single tenant, or "organizations" for multi tenant.')
param tenantId string

@description('Comma separated tenant IDs allowed to sign in. Required when tenantId is "organizations".')
param allowedTenantIds string = ''

@description('App registration (client) ID.')
param clientId string

@secure()
@description('App registration client secret.')
param clientSecret string

@secure()
@description('Session cookie signing secret, 32+ random characters.')
param sessionSecret string

@description('Public base URL override (for a custom domain). Leave empty to use the App Service default hostname.')
param baseUrl string = ''

@description('Days a download link stays valid; also the blob lifecycle delete threshold.')
@minValue(1)
param linkTtlDays int = 7

@minValue(1)
param maxUploadMb int = 100

@description('Uploads are buffered in memory; worst case memory is maxConcurrentUploads * maxUploadMb.')
@minValue(1)
param maxConcurrentUploads int = 4

@description('required: never serve a file without a clean Defender verdict (fail closed). best-effort: serve scanGraceMinutes after upload even without a verdict; unscanned files are served, malware is still blocked.')
@allowed(['best-effort', 'required'])
param scanPolicy string = 'required'

@minValue(0)
param scanGraceMinutes int = 2

@description('Defender for Storage malware scanning monthly cap in GB per storage account (-1 for unlimited).')
param scanCapGbPerMonth int = 500

param containerName string = 'uploads'

@description('Storage account name override (3-24 lowercase alphanumerics). Leave empty to derive a unique name.')
param storageAccountName string = ''

@description('Web app name override (globally unique). Leave empty to derive one.')
param webAppName string = ''

@description('Allow storage account key auth. False forces Entra auth only; the app uses managed identity so it does not need keys.')
param allowSharedKeyAccess bool = false

@description('Create the Storage Blob Data Owner assignment for the web app identity. Set false if the assignment already exists from a manual setup (ARM rejects a duplicate under a different name).')
param createRoleAssignment bool = true

@description('Create the Storage Table Data Contributor assignment the activity log needs. Set false only if it already exists under a different name.')
param createTableRoleAssignment bool = true

@description('Days upload and download records are kept in the activity log tables.')
@minValue(1)
param auditRetentionDays int = 730

@description('App role value (on the app registration) that grants access to the activity log page.')
param auditRole string = 'Audit.Read'

var suffix = uniqueString(resourceGroup().id, baseName)
var cleanBase = toLower(replace(baseName, '-', ''))
var storageName = empty(storageAccountName) ? take('st${cleanBase}${suffix}', 24) : storageAccountName
var siteName = empty(webAppName) ? '${baseName}-${suffix}' : webAppName
var effectivePlanName = empty(planName) ? 'asp-${baseName}' : planName
var effectiveStorageLocation = empty(storageLocation) ? location : storageLocation
var effectiveAppLocation = empty(appLocation) ? location : appLocation
var blobDataOwnerRoleId = 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b' // Storage Blob Data Owner (needed for scan result tag read)
var tableDataContributorRoleId = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3' // Storage Table Data Contributor (activity log)

// ---------------------------------------------------------------- Storage

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: effectiveStorageLocation
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
    allowSharedKeyAccess: allowSharedKeyAccess
    accessTier: 'Hot'
    publicNetworkAccess: 'Enabled'
    networkAcls: { defaultAction: 'Allow', bypass: 'AzureServices' }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    deleteRetentionPolicy: { enabled: false } // deleted means deleted; nothing lingers past the TTL
    containerDeleteRetentionPolicy: { enabled: false }
  }
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: containerName
  properties: { publicAccess: 'None' }
}

// Activity log. The lifecycle policy below only covers blobs, so these rows outlive the files; the app purges
// rows older than auditRetentionDays itself.
resource tableService 'Microsoft.Storage/storageAccounts/tableServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource uploadLogTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: tableService
  name: 'uploadlog'
}

resource downloadLogTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: tableService
  name: 'downloadlog'
}

resource lifecycle 'Microsoft.Storage/storageAccounts/managementPolicies@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          enabled: true
          name: 'delete-after-${linkTtlDays}-days'
          type: 'Lifecycle'
          definition: {
            actions: { baseBlob: { delete: { daysAfterCreationGreaterThan: linkTtlDays } } }
            filters: { blobTypes: ['blockBlob'] }
          }
        }
      ]
    }
  }
}

resource defender 'Microsoft.Security/defenderForStorageSettings@2025-01-01' = {
  name: 'current'
  scope: storage
  properties: {
    isEnabled: true
    malwareScanning: {
      onUpload: { isEnabled: true, capGBPerMonth: scanCapGbPerMonth }
    }
    sensitiveDataDiscovery: { isEnabled: false }
    overrideSubscriptionLevelSettings: true
  }
}

// ---------------------------------------------------------------- App Service

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: effectivePlanName
  location: effectiveAppLocation
  kind: 'linux'
  sku: { name: appServiceSku }
  properties: { reserved: true }
}

resource webApp 'Microsoft.Web/sites@2023-12-01' = {
  name: siteName
  location: effectiveAppLocation
  kind: 'app,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    clientAffinityEnabled: false
    siteConfig: {
      linuxFxVersion: 'NODE|${nodeVersion}'
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      http20Enabled: true
      alwaysOn: appServiceSku != 'F1'
      healthCheckPath: '/healthz'
    }
  }
}

var effectiveBaseUrl = empty(baseUrl) ? 'https://${webApp.properties.defaultHostName}' : baseUrl

// Separate config resource so BASE_URL can reference the site's real default hostname
resource appSettings 'Microsoft.Web/sites/config@2023-12-01' = {
  parent: webApp
  name: 'appsettings'
  properties: {
    // Oryx builds on deploy: npm install (including devDependencies for tsc) then npm run build
    SCM_DO_BUILD_DURING_DEPLOYMENT: 'true'
    ENABLE_ORYX_BUILD: 'true'
    WEBSITE_HTTPLOGGING_RETENTION_DAYS: '3'
    AUTHORITY_HOST: authorityHost
    TENANT_ID: tenantId
    ALLOWED_TENANT_IDS: allowedTenantIds
    CLIENT_ID: clientId
    CLIENT_SECRET: clientSecret
    BASE_URL: effectiveBaseUrl
    STORAGE_ACCOUNT: storage.name
    STORAGE_CONTAINER: containerName
    SESSION_SECRET: sessionSecret
    MAX_UPLOAD_MB: string(maxUploadMb)
    MAX_CONCURRENT_UPLOADS: string(maxConcurrentUploads)
    LINK_TTL_DAYS: string(linkTtlDays)
    SCAN_POLICY: scanPolicy
    SCAN_GRACE_MINUTES: string(scanGraceMinutes)
    AUDIT_RETENTION_DAYS: string(auditRetentionDays)
    AUDIT_ROLE: auditRole
  }
}

resource logs 'Microsoft.Web/sites/config@2023-12-01' = {
  parent: webApp
  name: 'logs'
  properties: {
    applicationLogs: { fileSystem: { level: 'Information' } }
    httpLogs: { fileSystem: { enabled: true, retentionInDays: 3, retentionInMb: 35 } }
    detailedErrorMessages: { enabled: false }
    failedRequestsTracing: { enabled: false }
  }
}

// Managed identity -> Storage Blob Data Owner on the storage account
resource blobOwner 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (createRoleAssignment) {
  name: guid(storage.id, webApp.id, blobDataOwnerRoleId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', blobDataOwnerRoleId)
    principalId: webApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Managed identity -> Storage Table Data Contributor on the storage account (activity log tables)
resource tableContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (createTableRoleAssignment) {
  name: guid(storage.id, webApp.id, tableDataContributorRoleId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', tableDataContributorRoleId)
    principalId: webApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---------------------------------------------------------------- Outputs

output webAppName string = webApp.name
output baseUrl string = effectiveBaseUrl
output storageAccountName string = storage.name
output storageAccountId string = storage.id
output principalId string = webApp.identity.principalId
output redirectUris array = [
  '${effectiveBaseUrl}/auth/callback'
  '${effectiveBaseUrl}/'
]
