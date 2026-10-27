#!/usr/bin/env bash
# Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.
set -euo pipefail

PREFIX="${1:-avd}"
ENV_NAME="${2:-dev}"
OUT_FILE="${3:-entra-manifest.json}"

echo "Checking Microsoft Graph sign-in and tenant SKUs..."
az rest --method GET --url "https://graph.microsoft.com/v1.0/subscribedSkus" --query "value[].skuPartNumber" -o tsv > /dev/null

echo "Validating Conditional Access template..."
python3 scripts/validate.py
echo "Entra preflight and template check complete for ${PREFIX}-${ENV_NAME} (output: ${OUT_FILE})."
