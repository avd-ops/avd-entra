#!/usr/bin/env bash
# Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLOUD="${AVD_CLOUD:-commercial}"
COMPLIANCE_PROFILE="${AVD_COMPLIANCE_PROFILE:-}"
POSITIONAL=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cloud)
      CLOUD="$2"
      shift 2
      ;;
    --cloud=*)
      CLOUD="${1#*=}"
      shift
      ;;
    --compliance-profile)
      COMPLIANCE_PROFILE="$2"
      shift 2
      ;;
    --compliance-profile=*)
      COMPLIANCE_PROFILE="${1#*=}"
      shift
      ;;
    --dry-run)
      AVD_OPS_DRY_RUN=1
      shift
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

PREFIX="${POSITIONAL[0]:-avd}"
ENV_NAME="${POSITIONAL[1]:-dev}"
OUT_FILE="${POSITIONAL[2]:-./entra-manifest.json}"
RUN_FILE="${POSITIONAL[3]:-./entra-run-manifest.json}"

if [[ -z "${COMPLIANCE_PROFILE}" ]]; then
  if [[ "${CLOUD}" == "usgov" ]]; then
    COMPLIANCE_PROFILE="itar-cui"
  else
    COMPLIANCE_PROFILE="standard"
  fi
fi

PWSH_ARGS=(
  -NoProfile
  -File "${SCRIPT_DIR}/Deploy-AvdEntra.ps1"
  -Cloud "${CLOUD}"
  -ComplianceProfile "${COMPLIANCE_PROFILE}"
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
echo "Entra deployment complete for ${PREFIX}-${ENV_NAME} (cloud: ${CLOUD}, profile: ${COMPLIANCE_PROFILE}, manifest: ${OUT_FILE})."
