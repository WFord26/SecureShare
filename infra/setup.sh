#!/usr/bin/env bash
# SecureShare Azure infrastructure setup
# Requires: az CLI logged in with Owner or Contributor + Security Admin on the subscription
set -euo pipefail

RG="${RG:-rg-secureshare}"
LOCATION="${LOCATION:-westus3}"
STORAGE="${STORAGE:-stsecureshare$RANDOM}"   # must be globally unique, lowercase, no symbols
CONTAINER="${CONTAINER:-uploads}"
TTL_DAYS="${TTL_DAYS:-7}"

echo "== Resource group =="
az group create --name "$RG" --location "$LOCATION" --output none

echo "== Storage account =="
az storage account create \
  --name "$STORAGE" \
  --resource-group "$RG" \
  --location "$LOCATION" \
  --sku Standard_LRS \
  --kind StorageV2 \
  --min-tls-version TLS1_2 \
  --allow-blob-public-access false \
  --allow-shared-key-access false \
  --output none

echo "== Private container =="
az storage container create \
  --name "$CONTAINER" \
  --account-name "$STORAGE" \
  --auth-mode login \
  --output none

echo "== Lifecycle policy: delete blobs $TTL_DAYS days after creation =="
cat > /tmp/lifecycle.json <<EOF
{
  "rules": [
    {
      "enabled": true,
      "name": "delete-after-${TTL_DAYS}-days",
      "type": "Lifecycle",
      "definition": {
        "actions": {
          "baseBlob": { "delete": { "daysAfterCreationGreaterThan": ${TTL_DAYS} } }
        },
        "filters": { "blobTypes": ["blockBlob"] }
      }
    }
  ]
}
EOF
az storage account management-policy create \
  --account-name "$STORAGE" \
  --resource-group "$RG" \
  --policy /tmp/lifecycle.json \
  --output none

echo "== Defender for Storage with on upload malware scanning =="
STORAGE_ID=$(az storage account show --name "$STORAGE" --resource-group "$RG" --query id -o tsv)
az rest --method PUT \
  --url "https://management.azure.com${STORAGE_ID}/providers/Microsoft.Security/defenderForStorageSettings/current?api-version=2022-12-01-preview" \
  --body '{
    "properties": {
      "isEnabled": true,
      "malwareScanning": {
        "onUpload": { "isEnabled": true, "capGBPerMonth": 500 }
      },
      "sensitiveDataDiscovery": { "isEnabled": false },
      "overrideSubscriptionLevelSettings": true
    }
  }' --output none

echo ""
echo "Done. Values for your .env:"
echo "  STORAGE_ACCOUNT=$STORAGE"
echo "  STORAGE_CONTAINER=$CONTAINER"
echo ""
echo "Next steps (see README):"
echo "  1. Create the Entra ID app registration"
echo "  2. Grant the app's identity 'Storage Blob Data Contributor' on the storage account"
echo "  3. Deploy the Node app (App Service, Container Apps, or a VM)"