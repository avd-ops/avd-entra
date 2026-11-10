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

    def test_c26_contract_matches_avd_assess(self) -> None:
        c26_path = ROOT / "contracts" / "cloud-environments.json"
        self.assertTrue(c26_path.is_file())
        c26 = json.loads(c26_path.read_text(encoding="utf-8"))
        self.assertEqual(c26["schema"], "avd-cloud-environments/v1")
        self.assertEqual(c26["clouds"]["commercial"]["graphEndpoint"], "https://graph.microsoft.com")
        self.assertEqual(c26["clouds"]["commercial"]["entraEnvironment"], "Global")
        self.assertEqual(c26["clouds"]["usgov"]["graphEndpoint"], "https://graph.microsoft.us")
        self.assertEqual(c26["clouds"]["usgov"]["entraEnvironment"], "USGov")
        self.assertEqual(c26["clouds"]["usgov"]["azCloudName"], "AzureUSGovernment")

    def test_manifest_schema_validation_catches_invalid_payloads(self) -> None:
        errors: list[str] = []
        validate.validate_manifest_data(
            {
                "schema": "wrong/v1",
                "cloud": "mars",
                "complianceProfile": "none",
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
        self.assertGreaterEqual(len(errors), 8)

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
            self.assertEqual(manifest["cloud"], "commercial")
            self.assertEqual(manifest["complianceProfile"], "standard")
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

    def test_usgov_deploy_and_itar_cui_offline_pwsh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            manifest_path = tmp_path / "entra-manifest.json"
            run_manifest_path = tmp_path / "entra-run-manifest.json"

            cmd = [
                "bash",
                str(ROOT / "scripts" / "deploy-entra.sh"),
                "--cloud",
                "usgov",
                "--dry-run",
                "avdgov",
                "prod",
                str(manifest_path),
                str(run_manifest_path),
            ]
            proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 0, msg=f"STDOUT: {proc.stdout}\nSTDERR: {proc.stderr}")

            errors = validate.validate_repo(manifest_path)
            self.assertEqual(errors, [])

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["cloud"], "usgov")
            self.assertEqual(manifest["complianceProfile"], "itar-cui")
            ca = manifest["conditionalAccess"][0]
            self.assertEqual(ca["complianceProfile"], "itar-cui")
            self.assertEqual(
                ca["authenticationStrength"],
                ["windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"],
            )

            run_manifest = json.loads(run_manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(run_manifest["cloud"], "usgov")
            self.assertEqual(run_manifest["complianceProfile"], "itar-cui")


if __name__ == "__main__":
    unittest.main()
