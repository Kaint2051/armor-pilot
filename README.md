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
2. Replace the placeholder administrator password in `k8s/secret.yaml`.
3. Pin the image tag in `k8s/deployment.yaml`.
4. Apply ArmorPilot:

```bash
kubectl apply -f k8s/
kubectl rollout status deployment/armor-pilot
```

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
flask --app app.main:app run --host 0.0.0.0 --port 5000
```

## Product configuration

New deployments use the `ARMORPILOT_*` environment variable prefix. Legacy
`VARMOR_*` licensing and installation variables remain accepted during the
transition. Names belonging to the upstream engine, including
`crd.varmor.org`, `VarmorPolicy`, and the vArmor log path, are intentionally
unchanged.

## Licensing and attribution

See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
