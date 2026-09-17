#!/usr/bin/env bash
# SecureShare: deploy infrastructure (Bicep) and the app (zip deploy with server side build).
# deploy.ps1 (PowerShell 7) does the same and also manages the Entra enterprise application; see README.
#
#   cp infra/deploy.env.example infra/deploy.env   # fill in
#   bash infra/deploy.sh                          # full deploy
#   bash infra/deploy.sh --infra-only             # Bicep only
#   bash infra/deploy.sh --app-only               # zip deploy only (resources must exist)
#
# Requires: az CLI (logged in), node + npm, zip.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
ENV_FILE="${ENV_FILE:-$HERE/deploy.env}"
MODE="${1:-all}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE. Copy infra/deploy.env.example to infra/deploy.env and fill it in." >&2
  exit 1
fi

# Load deploy.env (KEY=value lines, # comments, optional trailing comments).
# Filtered into a temp file first: macOS bash 3.2 does not reliably source a process substitution.
ENV_TMP="$(mktemp)"
trap 'rm -f "$ENV_TMP"' EXIT
sed -E 's/[[:space:]]+#.*$//; /^[[:space:]]*#/d; /^[[:space:]]*$/d' "$ENV_FILE" > "$ENV_TMP"
set -a
# shellcheck disable=SC1090
source "$ENV_TMP"
set +a

: "${RG:?RG is required}"
: "${LOCATION:?LOCATION is required}"
: "${TENANT_ID:?TENANT_ID is required}"
: "${CLIENT_ID:?CLIENT_ID is required}"
: "${CLIENT_SECRET:?CLIENT_SECRET is required}"
BASE_NAME="${BASE_NAME:-secureshare}"

# "az account show" answers from cache even when the refresh token has expired; asking for a token really checks
if ! az account get-access-token --output none 2>/dev/null; then
  echo "az CLI is not logged in or the token has expired. Run: az logout && az login" >&2
  exit 1
fi
if [[ -n "${SUBSCRIPTION:-}" ]]; then
  az account set --subscription "$SUBSCRIPTION"
fi
echo "== Subscription: $(az account show --query '[name, id]' -o tsv | paste -sd ' ' -)"

# Generate the session secret once and persist it so redeploys do not invalidate sessions
if [[ -z "${SESSION_SECRET:-}" ]]; then
  SESSION_SECRET="$(openssl rand -base64 48 | tr -d '\n')"
  export SESSION_SECRET
  if grep -qE '^SESSION_SECRET=' "$ENV_FILE"; then
    sed -i.bak -E "s|^SESSION_SECRET=.*$|SESSION_SECRET=${SESSION_SECRET//|/\\|}|" "$ENV_FILE" && rm -f "$ENV_FILE.bak"
  else
    printf '\nSESSION_SECRET=%s\n' "$SESSION_SECRET" >> "$ENV_FILE"
  fi
  echo "== Generated SESSION_SECRET and saved it to $ENV_FILE"
fi

DEPLOYMENT_NAME="secureshare-$(date +%Y%m%d-%H%M%S)"

if [[ "$MODE" != "--app-only" ]]; then
  echo "== Resource providers"
  az provider register --namespace Microsoft.Storage --wait --output none
  az provider register --namespace Microsoft.Web --wait --output none
  az provider register --namespace Microsoft.Security --wait --output none
  az provider register --namespace Microsoft.EventGrid --wait --output none   # required by Defender on-upload malware scanning

  if EXISTING_LOC="$(az group show --name "$RG" --query location -o tsv 2>/dev/null)" && [[ -n "$EXISTING_LOC" ]]; then
    echo "== Resource group $RG exists ($EXISTING_LOC)"
  else
    echo "== Creating resource group $RG ($LOCATION)"
    az group create --name "$RG" --location "$LOCATION" --output none
  fi

  echo "== Deploying infrastructure (Bicep)"
  az deployment group create \
    --name "$DEPLOYMENT_NAME" \
    --resource-group "$RG" \
    --parameters "$HERE/main.bicepparam" \
    --output none
  OUTPUTS="$(az deployment group show --name "$DEPLOYMENT_NAME" --resource-group "$RG" --query properties.outputs -o json)"
else
  # Reuse the most recent successful deployment's outputs, or fall back to the names in deploy.env
  LAST="$(az deployment group list --resource-group "$RG" --query "[?properties.provisioningState=='Succeeded' && starts_with(name, 'secureshare-')] | sort_by(@, &properties.timestamp) | [-1].name" -o tsv)"
  if [[ -n "$LAST" ]]; then
    OUTPUTS="$(az deployment group show --name "$LAST" --resource-group "$RG" --query properties.outputs -o json)"
  elif [[ -n "${WEB_APP_NAME:-}" ]]; then
    APP_HOST="$(az webapp show --resource-group "$RG" --name "$WEB_APP_NAME" --query defaultHostName -o tsv)"
    APP_PRINCIPAL="$(az webapp identity show --resource-group "$RG" --name "$WEB_APP_NAME" --query principalId -o tsv)"
    URL="${BASE_URL:-https://$APP_HOST}"
    OUTPUTS="$(python3 -c 'import json,sys; n,u,s,p=sys.argv[1:5]; print(json.dumps({"webAppName":{"value":n},"baseUrl":{"value":u},"storageAccountName":{"value":s},"principalId":{"value":p},"redirectUris":{"value":[u+"/auth/callback",u+"/"]}}))' "$WEB_APP_NAME" "$URL" "${STORAGE_ACCOUNT:-}" "$APP_PRINCIPAL")"
  else
    echo "No successful deployment found in $RG and WEB_APP_NAME is not set; run without --app-only first." >&2
    exit 1
  fi
fi

out() { python3 -c 'import json,sys; v=json.load(sys.stdin)[sys.argv[1]]["value"]; print("\n".join(v) if isinstance(v, list) else v)' "$1" <<<"$OUTPUTS"; }
WEB_APP="$(out webAppName)"
APP_URL="$(out baseUrl)"
STORAGE_NAME="$(out storageAccountName)"
PRINCIPAL_ID="$(out principalId)"
REDIRECT_URIS=()
while IFS= read -r line; do REDIRECT_URIS+=("$line"); done < <(out redirectUris)

if [[ "${UPDATE_APP_REG:-false}" == "true" ]]; then
  echo "== Adding redirect URIs to app registration $CLIENT_ID"
  # Graph PATCH of web.redirectUris only; "az ad app update --web-redirect-uris" rejects some registrations
  APP_OBJ="$(az ad app show --id "$CLIENT_ID" --query id -o tsv)"
  BODY="$(az ad app show --id "$CLIENT_ID" --query 'web.redirectUris' -o json | python3 -c '
import json,sys
existing=json.load(sys.stdin) or []
wanted=sys.argv[1:]
merged=sorted(set(existing)|set(wanted))
print(json.dumps({"web":{"redirectUris":merged}}))' "${REDIRECT_URIS[@]}")"
  az rest --method PATCH --url "https://graph.microsoft.com/v1.0/applications/$APP_OBJ" --headers "Content-Type=application/json" --body "$BODY" --output none
  echo "   Redirect URIs now: $(az ad app show --id "$CLIENT_ID" --query 'web.redirectUris' -o tsv | paste -sd ' ' -)"

  # Activity log app role. Existing roles are sent back unchanged: Graph replaces the whole appRoles list.
  AUDIT_ROLE="${AUDIT_ROLE:-Audit.Read}"
  ROLES_BODY="$(az ad app show --id "$CLIENT_ID" --query 'appRoles' -o json | python3 -c '
import json,sys,uuid
roles=json.load(sys.stdin) or []
value=sys.argv[1]
if any(r.get("value")==value for r in roles):
    sys.exit(0)
roles.append({"id":str(uuid.uuid4()),"value":value,"displayName":"Activity log reader","description":"View the SecureShare activity log: every upload, download and revoke","allowedMemberTypes":["User"],"isEnabled":True})
print(json.dumps({"appRoles":roles}))' "$AUDIT_ROLE")"
  if [[ -n "$ROLES_BODY" ]]; then
    echo "== Adding app role $AUDIT_ROLE to app registration $CLIENT_ID"
    az rest --method PATCH --url "https://graph.microsoft.com/v1.0/applications/$APP_OBJ" --headers "Content-Type=application/json" --body "$ROLES_BODY" --output none
  fi
fi

# Assign the activity log role to the people in AUDIT_USERS. Failures only warn: the app still deploys.
if [[ -n "${AUDIT_USERS:-}" ]]; then
  AUDIT_ROLE="${AUDIT_ROLE:-Audit.Read}"
  echo "== Assigning app role $AUDIT_ROLE"
  ROLE_ID="$(az ad app show --id "$CLIENT_ID" --query "appRoles[?value=='$AUDIT_ROLE'].id | [0]" -o tsv 2>/dev/null || true)"
  SP_ID="$(az ad sp show --id "$CLIENT_ID" --query id -o tsv 2>/dev/null || true)"
  if [[ -z "$SP_ID" ]]; then
    SP_ID="$(az ad sp create --id "$CLIENT_ID" --query id -o tsv 2>/dev/null || true)"
  fi
  if [[ -z "$ROLE_ID" || -z "$SP_ID" ]]; then
    echo "   WARNING: app role $AUDIT_ROLE or the enterprise application was not found; set UPDATE_APP_REG=true, or assign it in the portal (README: Activity log)." >&2
  else
    EXISTING="$(az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignedTo?\$top=999" --query "value[?appRoleId=='$ROLE_ID'].principalId" -o tsv 2>/dev/null || true)"
    IFS=',' read -r -a AUDITORS <<<"$AUDIT_USERS"
    for who in "${AUDITORS[@]}"; do
      who="$(echo "$who" | xargs)"
      [[ -z "$who" ]] && continue
      USER_ID="$(az ad user show --id "$who" --query id -o tsv 2>/dev/null || true)"
      if [[ -z "$USER_ID" ]]; then
        echo "   WARNING: user $who not found in this tenant" >&2
      elif grep -qx "$USER_ID" <<<"$EXISTING"; then
        echo "   $who already has $AUDIT_ROLE"
      elif az rest --method POST --url "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignedTo" --headers "Content-Type=application/json" \
          --body "{\"principalId\":\"$USER_ID\",\"resourceId\":\"$SP_ID\",\"appRoleId\":\"$ROLE_ID\"}" --output none; then
        echo "   Assigned $AUDIT_ROLE to $who (takes effect at their next sign in)"
      else
        echo "   WARNING: could not assign $AUDIT_ROLE to $who" >&2
      fi
    done
  fi
fi

if [[ "$MODE" != "--infra-only" ]]; then
  echo "== Packaging app"
  ZIP="$(mktemp -d)/secureshare.zip"
  (cd "$ROOT" && zip -qr "$ZIP" package.json package-lock.json tsconfig.json src public -x '*.DS_Store')
  echo "== Deploying app to $WEB_APP (App Service builds it with npm install + npm run build)"
  echo "   The status poll can keep saying 'Starting the site' after the site is already up; Ctrl+C at that point is harmless."
  az webapp deploy \
    --resource-group "$RG" \
    --name "$WEB_APP" \
    --src-path "$ZIP" \
    --type zip \
    --clean true \
    --restart true \
    --output none
  rm -f "$ZIP"
fi


cat <<SUMMARY

Done.
  Web app:          $WEB_APP
  URL:              $APP_URL
  Storage account:  $STORAGE_NAME
  Managed identity: $PRINCIPAL_ID (Storage Blob Data Owner and Storage Table Data Contributor on the storage account)
  Activity log:     $APP_URL/admin (app role ${AUDIT_ROLE:-Audit.Read})

Redirect URIs that must be on app registration $CLIENT_ID:
$(printf '  %s\n' "${REDIRECT_URIS[@]}")
$( [[ "${UPDATE_APP_REG:-false}" == "true" ]] || echo "  (set UPDATE_APP_REG=true in deploy.env to add them automatically, or add them in the portal)" )

Next:
  1. Wait 2-3 minutes for the first build; watch with:
       az webapp log tail --resource-group $RG --name $WEB_APP
  2. Open $APP_URL and follow the README test plan (text file, EICAR, encrypted zip, sign out).
  3. If uploads show "Storage error" or every download stays "scanning", the role assignment may still be
     propagating (up to ~5 minutes). Restart the app after that:
       az webapp restart --resource-group $RG --name $WEB_APP
SUMMARY
