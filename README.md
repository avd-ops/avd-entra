# avd-entra

Part of [avd-ops](https://avd-ops.dev/), the open toolkit for Azure Virtual Desktop.

> [!WARNING]
> **Personal project. Research and learning only. Not for production. No warranty.**
>
> - This is my own personal project, built on my own time **for research and learning**. It is **not affiliated with, endorsed by or supported by my employer**, Liquidware or Microsoft, and it does not represent their views, products or guidance.
> - **Do not run any of it in production** or against subscriptions and tenants that matter. Test it first in a dedicated lab subscription and tenant.
> - It is provided **"as is", without warranty of any kind**, under the [MIT License](LICENSE). You use it at your own risk.
> - **Contributions and forks are welcome and encouraged.** See [Contributing](#contributing).

## Role in avd-ops

Identity and zero-trust access control plane (`avd-entra`), orchestrated by [avd-landing-zone](https://github.com/avd-ops/avd-landing-zone) ([decision 0009](https://avd-ops.dev/docs/decisions/0009-split-landing-zone-into-five-control-planes.html)).

## What it does

- Creates per-pool Entra security groups, dynamic session-host device groups, and break-glass exclusion groups.
- Deploys Conditional Access policies targeting Azure Virtual Desktop and Windows Cloud Login app IDs (`reportOnly` by default).
- Completes Microsoft Graph service principal and Entra Kerberos readiness for Premium Azure Files (FSLogix).
- Seeds optional greenfield lab users and verifies/assigns license SKUs (`assignLicense`) without purchasing commitments.
- Driven from Azure Cloud Shell (`az rest`, PowerShell 7, Bash and Python) with redacted `entra-manifest.json` handoff output.

## Contracts

Produces `entra-manifest.json` (logical group roles, dynamic device membership rules, Conditional Access baseline state, and Entra Kerberos readiness) consumed by `avd-intune`, `avd-m365`, `avd-azure` and `avd-power-platform`.

## Contributing

Fork it, open an issue or a pull request. Follow the family guardrails in [AGENTS.md](AGENTS.md): no tenant IDs, secrets, domains or customer names, and propose changes via pull request only. Contributions are accepted under the [MIT License](LICENSE).

## License and disclaimer

[MIT](LICENSE). Personal project, not for production, provided as is, not affiliated with the author's employer, Liquidware or Microsoft.
