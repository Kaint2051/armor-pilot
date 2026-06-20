# ArmorPilot

ArmorPilot is a Kubernetes runtime security management platform powered by the
open-source [vArmor](https://github.com/bytedance/vArmor) enforcement engine.
It provides policy creation, review workflows, audit visibility, access
control, behavior-model management, and commercial license activation.

ArmorPilot is an independent product. It is not affiliated with, endorsed by,
or an official distribution of the vArmor project or ByteDance.

## Architecture

```text
ArmorPilot Web UI and API
          |
          v
Kubernetes API and vArmor CRDs
          |
          v
vArmor Manager and Agents
          |
          v
AppArmor / BPF LSM / Seccomp / NetworkProxy
```

## Container images

Published releases contain two deliberately separate images:

```text
ghcr.io/kaint2051/armor-pilot:<version>             # Community
ghcr.io/kaint2051/armor-pilot-enterprise:<version>  # Commercial
```

The Community image does not contain Enterprise template payloads. The
Enterprise image contains the licensed payloads, but compiles Python backend
modules into native extensions and does not ship `.py` source files.

Use a versioned tag or digest in production instead of `latest`. The Enterprise
package should remain private and be granted only to licensed customers.

## Kubernetes installation

1. Install vArmor and confirm its CRDs and agents are ready.
2. Pin the Enterprise image tag or digest in `k8s/deployment.yaml`.
3. Create a private environment file:

```bash
cp .env.example .env
chmod 600 .env
```

4. Replace `ADMIN_PASS` and review every setting in `.env`.
5. Deploy with one of the provided scripts:

```bash
./scripts/deploy.sh .env
```

```powershell
Copy-Item .env.example .env
.\scripts\deploy.ps1 -EnvFile .env
```

The deployment script creates or updates the Kubernetes Secret
`armor-pilot-secret` from the private env file, applies the manifests, and
waits for the rollout. The Deployment imports configuration through
`envFrom`; no credential values are stored in the manifest.

The default manifest exposes ArmorPilot through NodePort `30080`.

## Migrating an existing installation

The rebrand changes Kubernetes resource names from the legacy console name to
`armor-pilot` and changes the default host data directory to
`/var/lib/armor-pilot`. Before replacing an existing deployment:

1. Back up the old `/app/data` volume, including the user database,
   installation identity, and installed license.
2. Restore that data into the new ArmorPilot volume.
3. Deploy the new manifests and verify the Installation ID is unchanged.
4. Remove the legacy Kubernetes resources only after ArmorPilot is healthy.

Applying the new manifests alone does not rename or remove legacy resources.

## Local development

```bash
pip install -r requirements.txt
npm install
npm run build:css
cp .env.example .env
# Configure ADMIN_USER and ADMIN_PASS in .env.
flask --app app.main:app run --host 0.0.0.0 --port 5000
```

## Product configuration

New deployments use the `ARMORPILOT_*` environment variable prefix. Legacy
`VARMOR_*` licensing and installation variables remain accepted during the
transition. Names belonging to the upstream engine, including
`crd.varmor.org`, `VarmorPolicy`, and the vArmor log path, are intentionally
unchanged.

The `.env` file is excluded by Git and Docker. Keep the production copy outside
the repository when possible, for example:

```bash
sudo install -m 600 .env /etc/armor-pilot/armor-pilot.env
./scripts/deploy.sh /etc/armor-pilot/armor-pilot.env
```

Kubernetes Secrets are base64-encoded, not encrypted by default. Restrict RBAC
access to Secrets and enable Kubernetes encryption at rest for production
clusters.

Production images run as UID/GID `10001`, use a read-only root filesystem, and
write only to `/app/data` and `/tmp`. The deployment includes a narrowly scoped
init container that corrects ownership on the persistent data directory.

`ADMIN_USER` and `ADMIN_PASS` seed the first administrator only when the user
database is empty. Rotate an existing account password through ArmorPilot's
Access Control screen instead of editing `.env`.

## Documentation

| Document | Description |
|---|---|
| [System Overview](docs/SYSTEM_OVERVIEW.md) | Architecture, components, policy modes, enforcement engines, RBAC, and API endpoints |
| [User Guide](docs/USER_GUIDE.md) | Login, dashboard, policy management, backup and restore, license management, and audit logs |
| [Practical Labs](docs/PRACTICAL_LABS.md) | Hands-on attack and defense labs using vArmor policies (tiếng Việt) |
| [Open Core Model](docs/OPEN_CORE.md) | Community vs Enterprise edition split and template pack catalogue |
| [Commercial Build](docs/COMMERCIAL_BUILD.md) | Enterprise container build, signing key management, and CI/CD configuration |
| [Licensing](docs/LICENSING.md) | Offline license activation, installation ID, and license key format |
| [License Pricing](docs/LICENSE_PRICING.md) | Pricing guide and commercial subscription model (internal) |
| [License Issuer Guide](docs/LICENSE_ISSUER_GUIDE.md) | Vendor signing key operations and license issuance workflow |

## Licensing and attribution

See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
Commercial image build and key-handling instructions are in
[docs/COMMERCIAL_BUILD.md](docs/COMMERCIAL_BUILD.md). License activation,
pricing, and issuance procedures are in the docs above.
