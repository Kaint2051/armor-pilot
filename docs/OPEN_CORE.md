# ArmorPilot Open Core Plan

This project follows an open-core product split:

- **Community**: usable self-managed console with core policy workflows and general-purpose templates.
- **Enterprise**: signed-license add-ons for high-value template packs and commercial support workflows.

The goal is to make the core product trustworthy and useful while keeping the commercial value in curated, supportable, license-gated packs.

## Editions

| Edition | License | Intended use |
| --- | --- | --- |
| Community | Not required | Evaluation, labs, small teams, core vArmor policy operations |
| Enterprise | Signed license | Production security teams that need curated packs, support, and packaged guidance |
| Developer | Fail-open local/dev mode | Internal development and demos only |

## Community Template Packs

These packs are open-core and always available when the console is running in enforced licensing mode:

- `baseline`: baseline hardening and observe-first policies
- `cve`: focused CVE and escape-path mitigations
- `compliance`: general compliance-oriented guardrails
- `workload`: common application workload profiles
- `network`: NetworkProxy and egress-control starters

## Enterprise Template Packs

These packs are license-gated:

| Pack | Feature flag | Value |
| --- | --- | --- |
| `data-protection` | `templates:data_protection` | Secrets, TLS keys, backup controllers, sensitive data paths |
| `platform-infra` | `templates:platform_infra` | Databases, brokers, auth, DNS, CSI, CNI, admission controllers |
| `incident-response` | `templates:incident_response` | Emergency lockdown, forensics, crypto-miner containment |

Use `templates:*` or `*` only for full-enterprise/internal licenses.

## Runtime Behavior

When `ARMORPILOT_LICENSE_REQUIRED=true`:

- Missing or invalid license with `ARMORPILOT_LICENSE_FAIL_OPEN=false` = fail-closed commercial mode.
- Missing or invalid license with fail-open enabled = Community/evaluation behavior.
- Valid license = Enterprise features listed in the signed license are enabled.
- Locked enterprise packs are hidden from `/api/policy-templates` and returned as `locked_packs`.

When `ARMORPILOT_LICENSE_REQUIRED=false`:

- The console runs in Developer edition.
- All features are visible to avoid breaking labs and internal demos.
- This mode should not be used for customer production delivery.

## Product API

The console exposes product metadata:

- `GET /api/product`: edition matrix, feature catalog, core/enterprise pack split.
- `GET /api/license`: license status plus the same product metadata.
- `GET /api/policy-templates`: visible template packs, templates, and `locked_packs`.

## Packaging Notes

The next commercial hardening step should be a production image profile:

- no development docs/tools/labs in runtime image
- non-root runtime user
- signed container images
- build revision and customer/build watermark
- private registry delivery

Obfuscation or compilation can come after this split is stable.
