# Contracts for avd-entra

- `entra-manifest.schema.json`: Validates `entra-manifest.json` (target `cloud` (`"commercial"` | `"usgov"`), `complianceProfile` (`"standard"` | `"itar-cui"`), logical group roles including optional Windows 365 user and dynamic Cloud PC device groups, dynamic device membership rules, Conditional Access baseline state, and Entra Kerberos readiness) consumed by `avd-intune`, `avd-m365`, `avd-azure` and `avd-power-platform`. `entra-run-manifest.json` also stamps `cloud` and `complianceProfile` for fail-closed teardown verification.
- `cloud-environments.json` (`C26`, `avd-cloud-environments/v1`): Pinned canonical cloud environment map from `avd-assess` defining endpoints (`https://graph.microsoft.com` / `https://graph.microsoft.us`, `https://login.microsoftonline.com` / `https://login.microsoftonline.us`), `MgGraph` environments (`Global` / `USGov`), and capabilities for `commercial` and `usgov` (Azure US Government + Microsoft 365 GCC High).

See [avd-ops decision 0009](https://avd-ops.dev/docs/decisions/0009-split-landing-zone-into-five-control-planes.html), [decision 0012](https://avd-ops.dev/docs/decisions/0012-desktop-devops-for-avd-win365-and-intune.html), and [decision 0013](https://avd-ops.dev/docs/decisions/0013-azure-us-government-and-gcc-high-support.html).

