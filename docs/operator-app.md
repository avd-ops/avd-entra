# Opt-in Operator Enterprise App (`Initialize-AvdOperatorApp.ps1`)

> Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.

`scripts/Initialize-AvdOperatorApp.ps1` is an **opt-in** bootstrap for lab and CI automation where one-time Privileged Role Administrator or Global Administrator consent is available. Production and split-governance organizations should continue using interactive/PIM-activated admins.

## Key Guardrails

- **GitHub environment protection:** The GitHub environment bound to the federated credential **must** require reviewer approval and restrict deployment branches to the default branch.
- **Lab and CI only:** `-Environment prod` is refused unless `-ConfirmProd` is explicitly passed.
- **US Government (`usgov`):** `-Cloud usgov` (GCC High) is untested until a first recorded run and fails closed unless `-AllowUntestedUsGov` is passed.
- **Intune scope tags:** Microsoft Graph application permissions are tenant-wide and bypass Intune RBAC scope tags.
- **No stored secrets:** An app management policy blocking `passwordAddition`, `customPasswordAddition`, and `symmetricKeyAddition` is applied before any permissions are consented.
