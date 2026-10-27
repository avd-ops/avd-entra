#!/usr/bin/env python3
# Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.
"""Offline unit tests for avd-entra control plane scripts and contract validator."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import validate  # noqa: E402


class TestEntraControlPlane(unittest.TestCase):
    def test_repo_validation_passes(self) -> None:
        errors = validate.validate_repo()
        self.assertEqual(errors, [])

    def test_manifest_schema_validation_catches_invalid_payloads(self) -> None:
        errors: list[str] = []
        validate.validate_manifest_data(
            {
                "schema": "wrong/v1",
                "environment": "staging",
                "prefix": "a",
                "groups": {},
                "conditionalAccess": [{"displayName": "x", "state": "invalid", "policyId": ""}],
                "entraKerberosReady": "yes",
                "extraKey": True,
            },
            "bad-manifest.json",
            errors,
        )
        self.assertGreaterEqual(len(errors), 6)

    def test_deploy_and_teardown_offline_pwsh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            manifest_path = tmp_path / "entra-manifest.json"
            run_manifest_path = tmp_path / "entra-run-manifest.json"

            cmd = [
                "pwsh",
                "-NoProfile",
                "-File",
                str(ROOT / "scripts" / "Deploy-AvdEntra.ps1"),
                "-Prefix",
                "avd",
                "-Environment",
                "dev",
                "-StorageAccountFqdn",
                "stavddev01.file.core.windows.net",
                "-InitializeGraphApp",
                "-SeedLabUsers",
                "-OutputPath",
                str(manifest_path),
                "-RunManifestPath",
                str(run_manifest_path),
                "-DryRun",
            ]
            proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 0, msg=f"STDOUT: {proc.stdout}\nSTDERR: {proc.stderr}")
            self.assertTrue(manifest_path.is_file())
            self.assertTrue(run_manifest_path.is_file())

            errors = validate.validate_repo(manifest_path)
            self.assertEqual(errors, [])

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema"], "avd-ops-entra-manifest/v1")
            self.assertTrue(manifest["entraKerberosReady"])
            self.assertEqual(manifest["conditionalAccess"][0]["state"], "enabledForReportingButNotEnforced")

            # Verify teardown without -DiscardLastCopy fails on stateful resources
            rm_fail = subprocess.run(
                [
                    "pwsh",
                    "-NoProfile",
                    "-Command",
                    f"& '{ROOT / 'scripts' / 'Remove-AvdEntra.ps1'}' -RunManifestPath '{run_manifest_path}' -DryRun -Confirm:$false",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(rm_fail.returncode, 0)
            self.assertIn("DiscardLastCopy", rm_fail.stderr + rm_fail.stdout)

            # Verify teardown with -DiscardLastCopy succeeds
            rm_ok = subprocess.run(
                [
                    "pwsh",
                    "-NoProfile",
                    "-Command",
                    f"& '{ROOT / 'scripts' / 'Remove-AvdEntra.ps1'}' -RunManifestPath '{run_manifest_path}' -DiscardLastCopy -DryRun -Confirm:$false",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(rm_ok.returncode, 0, msg=f"STDOUT: {rm_ok.stdout}\nSTDERR: {rm_ok.stderr}")


if __name__ == "__main__":
    unittest.main()
