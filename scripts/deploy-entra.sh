#!/usr/bin/env bash
# Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${1:-avd}"
ENV_NAME="${2:-dev}"
OUT_FILE="${3:-./entra-manifest.json}"
RUN_FILE="${4:-./entra-run-manifest.json}"

PWSH_ARGS=(
  -NoProfile
  -File "${SCRIPT_DIR}/Deploy-AvdEntra.ps1"
  -Prefix "${PREFIX}"
  -Environment "${ENV_NAME}"
  -OutputPath "${OUT_FILE}"
  -RunManifestPath "${RUN_FILE}"
)

if [[ "${AVD_OPS_DRY_RUN:-0}" == "1" ]]; then
  PWSH_ARGS+=(-DryRun)
fi

if [[ -n "${AVD_STORAGE_FQDN:-}" ]]; then
  PWSH_ARGS+=(-StorageAccountFqdn "${AVD_STORAGE_FQDN}")
fi

if [[ "${AVD_INIT_GRAPH_APP:-0}" == "1" ]]; then
  PWSH_ARGS+=(-InitializeGraphApp)
fi

if [[ "${AVD_SEED_LAB_USERS:-0}" == "1" ]]; then
  PWSH_ARGS+=(-SeedLabUsers)
fi

pwsh "${PWSH_ARGS[@]}"
echo "Entra deployment complete for ${PREFIX}-${ENV_NAME} (manifest: ${OUT_FILE})."
