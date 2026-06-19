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

## Container image

Published releases use:

```text
ghcr.io/kaint2051/armor-pilot:<version>
```

Use a versioned tag in production instead of `latest`.

## Kubernetes installation

1. Install vArmor and confirm its CRDs and agents are ready.
2. Pin the image tag in `k8s/deployment.yaml`.
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

`ADMIN_USER` and `ADMIN_PASS` seed the first administrator only when the user
database is empty. Rotate an existing account password through ArmorPilot's
Access Control screen instead of editing `.env`.

## Licensing and attribution

See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
