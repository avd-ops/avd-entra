#!/usr/bin/env python3
# Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.
"""Validate all JSON templates, contract schemas, and no-leak guardrails in this repository."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
ALLOWED_DOMAINS = ("example.com", "contoso.com", "users.noreply.github.com")
VALID_ENVS = ("dev", "test", "prod")
VALID_CA_STATES = ("enabledForReportingButNotEnforced", "enabled", "disabled")
REQUIRED_ROOT_KEYS = {
    "schema",
    "environment",
    "prefix",
    "groups",
    "conditionalAccess",
    "entraKerberosReady",
}
REQUIRED_GROUP_KEYS = {
    "avdUsersGroupId",
    "avdAdminsGroupId",
    "sessionHostsDynamicGroupId",
    "breakGlassExcludeGroupId",
}


def validate_manifest_data(data: Any, label: str, errors: list[str]) -> None:
    if not isinstance(data, dict):
        errors.append(f"{label}: manifest root must be a JSON object")
        return

    extra_keys = set(data.keys()) - REQUIRED_ROOT_KEYS
    missing_keys = REQUIRED_ROOT_KEYS - set(data.keys())
    if missing_keys:
        errors.append(f"{label}: missing required keys: {sorted(missing_keys)}")
    if extra_keys:
        errors.append(f"{label}: unexpected keys not allowed by schema: {sorted(extra_keys)}")

    if data.get("schema") != "avd-ops-entra-manifest/v1":
        errors.append(f"{label}: schema must be 'avd-ops-entra-manifest/v1', got {data.get('schema')!r}")

    env = data.get("environment")
    if env not in VALID_ENVS:
        errors.append(f"{label}: environment must be one of {VALID_ENVS}, got {env!r}")

    prefix = data.get("prefix")
    if not isinstance(prefix, str) or len(prefix) < 2:
        errors.append(f"{label}: prefix must be a string of minLength 2, got {prefix!r}")

    groups = data.get("groups")
    if not isinstance(groups, dict):
        errors.append(f"{label}: groups must be an object")
    else:
        for gk in REQUIRED_GROUP_KEYS:
            gv = groups.get(gk)
            if not isinstance(gv, str) or not gv.strip():
                errors.append(f"{label}: groups.{gk} must be a non-empty string")

    ca_list = data.get("conditionalAccess")
    if not isinstance(ca_list, list):
        errors.append(f"{label}: conditionalAccess must be an array")
    else:
        for idx, item in enumerate(ca_list):
            if not isinstance(item, dict):
                errors.append(f"{label}: conditionalAccess[{idx}] must be an object")
                continue
            for req_k in ("displayName", "state", "policyId"):
                if not isinstance(item.get(req_k), str) or not item.get(req_k, "").strip():
                    errors.append(f"{label}: conditionalAccess[{idx}].{req_k} must be a non-empty string")
            if item.get("state") not in VALID_CA_STATES:
                errors.append(
                    f"{label}: conditionalAccess[{idx}].state must be one of {VALID_CA_STATES}, got {item.get('state')!r}"
                )

    kerb = data.get("entraKerberosReady")
    if not isinstance(kerb, bool):
        errors.append(f"{label}: entraKerberosReady must be a boolean, got {kerb!r}")


def validate_repo(manifest_path: Path | None = None) -> list[str]:
    errors: list[str] = []

    schema_file = ROOT / "contracts" / "entra-manifest.schema.json"
    if not schema_file.is_file():
        errors.append("contracts/entra-manifest.schema.json: missing contract schema file")

    for jf in ROOT.rglob("*.json"):
        if ".git" in jf.parts:
            continue
        rel = jf.relative_to(ROOT)
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"{rel}: invalid JSON: {exc}")
            continue
        if not isinstance(data, (dict, list)):
            errors.append(f"{rel}: root must be object or array")
            continue

        if jf.parent == ROOT / "policies" / "conditional-access" and isinstance(data, dict):
            for req in ("displayName", "state", "conditions"):
                if req not in data:
                    errors.append(f"{rel}: missing required key '{req}'")
            if data.get("state") not in VALID_CA_STATES:
                errors.append(f"{rel}: invalid state {data.get('state')!r}")

    for shf in ROOT.rglob("*.sh"):
        if ".git" in shf.parts:
            continue
        raw_bytes = shf.read_bytes()
        if b"\r\n" in raw_bytes:
            errors.append(f"{shf.relative_to(ROOT)}: contains CRLF line endings; must use LF (\\n)")

    for tf in ROOT.rglob("*"):
        if ".git" in tf.parts or not tf.is_file():
            continue
        try:
            text = tf.read_text(encoding="utf-8")
        except Exception:
            continue
        for m in EMAIL.finditer(text):
            addr = m.group(0)
            if not any(addr.endswith("@" + d) for d in ALLOWED_DOMAINS):
                errors.append(f"{tf.relative_to(ROOT)}: disallowed email address {addr}")

    if manifest_path is not None:
        if not manifest_path.is_file():
            errors.append(f"{manifest_path}: manifest file does not exist")
        else:
            try:
                manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
                validate_manifest_data(manifest_data, str(manifest_path), errors)
            except Exception as exc:
                errors.append(f"{manifest_path}: invalid JSON: {exc}")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=None, help="Path to an entra-manifest.json file to validate")
    args = parser.parse_args(argv)

    errors = validate_repo(args.manifest)
    if errors:
        for e in errors:
            print(f"::error::{e}")
        return 1

    print("All JSON templates, schemas, and leak checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
