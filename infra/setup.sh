#!/usr/bin/env bash
# SecureShare Azure infrastructure setup (global / US commercial Azure)
# Requires: az CLI logged in with Owner or Contributor + Security Admin on the subscription
#
#   RG=rg-secureshare LOCATION=westus3 bash setup.sh
#
# Optional: STORAGE (globally unique name), CONTAINER, TTL_DAYS, SCAN_CAP_GB, SUBSCRIPTION
set -euo pipefail

RG="${RG:-rg-secureshare}"
LOCATION="${LOCATION:-westus3}"
STORAGE="${STORAGE:-stsecureshare$RANDOM$RANDOM}"   # must be globally unique, 3-24 lowercase alphanumerics
CONTAINER="${CONTAINER:-uploads}"
TTL_DAYS="${TTL_DAYS:-7}"
SCAN_CAP_GB="${SCAN_CAP_GB:-500}"                   # Defender malware scanning monthly cap per storage account

if [[ -n "${SUBSCRIPTION:-}" ]]; then
  az account set --subscription "$SUBSCRIPTION"
fi
echo "== Using subscription: $(az account show --query '[name, id, environmentName]' -o tsv | paste -sd ' ' -) =="

echo "== Resource providers =="
az provider register --namespace Microsoft.Storage --wait --output none
az provider register --namespace Microsoft.Security --wait --output none
az provider register --namespace Microsoft.EventGrid --wait --output none   # required by Defender on-upload malware scanning

echo "== Resource group $RG ($LOCATION) =="
az group create --name "$RG" --location "$LOCATION" --output none

echo "== Storage account $STORAGE =="
az storage account create \
  --name "$STORAGE" \
  --resource-group "$RG" \
  --location "$LOCATION" \
  --sku Standard_LRS \
  --kind StorageV2 \
  --min-tls-version TLS1_2 \
  --allow-blob-public-access false \
  --https-only true \
  --output none

echo "== Private container $CONTAINER =="
# Control plane call: works with Contributor alone, no data plane role or key needed
az storage container-rm create \
  --storage-account "$STORAGE" \
  --resource-group "$RG" \
  --name "$CONTAINER" \
  --public-access off \
  --output none

echo "== Lifecycle policy: delete blobs $TTL_DAYS days after creation =="
POLICY="$(mktemp)"
cat > "$POLICY" <<JSON
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
JSON
az storage account management-policy create \
  --account-name "$STORAGE" \
  --resource-group "$RG" \
  --policy "@$POLICY" \
  --output none
rm -f "$POLICY"

echo "== Defender for Storage with on upload malware scanning (cap ${SCAN_CAP_GB} GB/month) =="
STORAGE_ID=$(az storage account show --name "$STORAGE" --resource-group "$RG" --query id -o tsv)
az rest --method PUT \
  --url "https://management.azure.com${STORAGE_ID}/providers/Microsoft.Security/defenderForStorageSettings/current?api-version=2025-01-01" \
  --body "{
    \"properties\": {
      \"isEnabled\": true,
      \"malwareScanning\": {
        \"onUpload\": { \"isEnabled\": true, \"capGBPerMonth\": ${SCAN_CAP_GB} }
      },
      \"sensitiveDataDiscovery\": { \"isEnabled\": false },
      \"overrideSubscriptionLevelSettings\": true
    }
  }" --output none

echo ""
echo "Done. Values for your .env / App Service settings:"
echo "  STORAGE_ACCOUNT=$STORAGE"
echo "  STORAGE_CONTAINER=$CONTAINER"
echo ""
echo "Storage account resource ID (scope for role assignments):"
echo "  $STORAGE_ID"
echo ""
echo "Next steps (see README):"
echo "  1. Create the Entra ID app registration (global tenant: portal.azure.com)"
echo "  2. Grant the app's identity both roles on the storage account:"
echo "       az role assignment create --assignee <principalId> --role \"Storage Blob Data Owner\" --scope \"$STORAGE_ID\""
echo "     (Data Owner is required to read the Defender scan result tags; Data Contributor alone is not enough)"
echo "  3. Deploy the Node app (App Service, Container Apps, or a VM)"
echo "  4. Defender enablement can take a few minutes; test with an EICAR file before go live"
