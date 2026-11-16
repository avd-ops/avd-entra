# avd-entra

Part of [avd-ops](https://avd-ops.dev/), the open toolkit for Azure Virtual Desktop.

Identity and zero-trust access control plane (`avd-entra`) for Desktop DevOps across Azure Virtual Desktop and Windows 365, orchestrated by [avd-landing-zone](https://github.com/avd-ops/avd-landing-zone#readme) ([avd-ops docs](https://avd-ops.dev/docs/repos/avd-entra.html), [decision 0009](https://avd-ops.dev/docs/decisions/0009-split-landing-zone-into-five-control-planes.html), [decision 0012](https://avd-ops.dev/docs/decisions/0012-desktop-devops-for-avd-win365-and-intune.html)).

> [!WARNING]
> **Personal project. Research and learning only. Not for production. No warranty.**
>
> - This is my own personal project, built on my own time **for research and learning**. It is **not affiliated with, endorsed by or supported by my employer**, Liquidware or Microsoft, and it does not represent their views, products or guidance.
> - **Do not run any of it in production** or against subscriptions and tenants that matter. Test it first in a dedicated lab subscription and tenant.
> - It is provided **"as is", without warranty of any kind**, under the [MIT License](LICENSE). You use it at your own risk.
> - **Contributions and forks are welcome and encouraged.** See [Contributing](#contributing).

## How it connects

| Direction | Repo | Relationship |
|---|---|---|
| Front door | [avd-ops](https://github.com/avd-ops/avd-ops#readme) | Overview, [repo page](https://avd-ops.dev/docs/repos/avd-entra.html), and platform decisions |
| Orchestrator | [avd-landing-zone](https://github.com/avd-ops/avd-landing-zone#readme) | Invokes `avd-entra` first in the multi-plane deployment pipeline |
| Downstream | [avd-intune](https://github.com/avd-ops/avd-intune#readme) | Consumes `entra-manifest.json` device and user group targets |
| Downstream | [avd-m365](https://github.com/avd-ops/avd-m365#readme) | Consumes `entra-manifest.json` user group targets |
| Downstream | [avd-azure](https://github.com/avd-ops/avd-azure#readme) | Consumes `entra-manifest.json` for application group RBAC and Entra Kerberos |
| Downstream | [avd-power-platform](https://github.com/avd-ops/avd-power-platform#readme) | Consumes `entra-manifest.json` for approval and self-service groups |
| Assess & remediate | [avd-assess](https://github.com/avd-ops/avd-assess#readme) / [avd-remediate](https://github.com/avd-ops/avd-remediate#readme) | Identity standards (`methods/entra.md`) and `C24` remediation plane |

## What it does

- Creates per-pool Entra security groups, dynamic session-host device groups, optional Windows 365 user and dynamic Cloud PC device groups (`-IncludeWin365`), and break-glass exclusion groups.
- Deploys Conditional Access policies targeting Azure Virtual Desktop (`9cdead84-a844-4324-93f2-b2e6bb768d07`), Windows Cloud Login (`270efc09-cd0d-444b-a71f-39af4910ec45`), and Windows 365 (`0af06dc6-e4b5-4f28-818e-e78e62d137a5`) app IDs (`reportOnly` by default).
- Completes Microsoft Graph service principal and Entra Kerberos readiness for Premium Azure Files (FSLogix).
- Seeds optional greenfield lab users and verifies/assigns license SKUs (`assignLicense`) without purchasing commitments.
- Driven from Azure Cloud Shell (`az rest`, PowerShell 7, Bash and Python) with redacted `entra-manifest.json` handoff output.

## Contracts

Produces `entra-manifest.json` (logical group roles, dynamic device membership rules, Conditional Access baseline state, and Entra Kerberos readiness) consumed by [avd-intune](https://github.com/avd-ops/avd-intune#readme), [avd-m365](https://github.com/avd-ops/avd-m365#readme), [avd-azure](https://github.com/avd-ops/avd-azure#readme), and [avd-power-platform](https://github.com/avd-ops/avd-power-platform#readme).

## Docs

- Agent instructions & guardrails: [AGENTS.md](AGENTS.md)
- Repo page on avd-ops: [avd-ops.dev/docs/repos/avd-entra](https://avd-ops.dev/docs/repos/avd-entra.html)

## Contributing

Fork it, open an issue or a pull request. Follow the family guardrails in [AGENTS.md](AGENTS.md): no tenant IDs, secrets, domains or customer names, and propose changes via pull request only. Contributions are accepted under the [MIT License](LICENSE).

## License and disclaimer

[MIT](LICENSE). Personal project, not for production, provided as is, not affiliated with the author's employer, Liquidware or Microsoft.
