# vArmor Console Licensing

The console verifies compact signed license keys and legacy JSON licenses. Keep the private key offline. The
production product should embed the Ed25519 public key in the backend build so
customers cannot replace the trust anchor through the web UI or a Kubernetes
Secret.

## Generate Signing Keys

```bash
python tools/license_tool.py gen-key \
  --private-key license-private.pem \
  --public-key license-public.pem
```

The command prints `VARMOR_LICENSE_PUBLIC_KEY`. For production, replace
`EMBEDDED_LICENSE_PUBLIC_KEY` in `app/license.py` before building the product
image. For development only, you can set `VARMOR_LICENSE_ALLOW_ENV_PUBLIC_KEY=true`
and provide `VARMOR_LICENSE_PUBLIC_KEY` through the environment.

## Generate a Customer License Key

```bash
python tools/license_tool.py sign \
  --private-key license-private.pem \
  --output customer-license.key \
  --license-id LIC-ACME-001 \
  --customer "ACME Corp" \
  --edition enterprise \
  --days 365 \
  --grace-days 7 \
  --features "templates:data_protection,templates:platform_infra,templates:incident_response" \
  --max-nodes 100 \
  --max-policies 500
```

The output is one signed line:

```text
VARMOR1.<base64url-payload>.<ed25519-signature>
```

The customer pastes this key into **Console > Users > License > Install
License**. Use `--features "*"` for a full enterprise license. Legacy JSON can
still be generated with `--format json` and remains accepted by the console.

Open-core enterprise feature flags currently implemented:

- `templates:data_protection`
- `templates:platform_infra`
- `templates:incident_response`
- `templates:*` for every enterprise template pack
- `*` for internal/full-access licenses

## Verify Before Delivery

```bash
python tools/license_tool.py verify \
  --public-key license-public.pem \
  --license customer-license.key
```

## Runtime Configuration

Set these environment variables in the console deployment:

- `VARMOR_LICENSE_FILE`: path to the uploaded license file, default `/app/data/license.json`.
- `VARMOR_LICENSE_REQUIRED`: `true` to enforce licensed features.
- `VARMOR_LICENSE_FAIL_OPEN`: set to `false` for commercial builds.
- `VARMOR_LICENSE_ALLOW_ENV_PUBLIC_KEY`: development escape hatch only. Keep `false` in production.
- `VARMOR_LICENSE_PUBLIC_KEY`: base64 Ed25519 public key, used only when the env public-key override is enabled.
- `VARMOR_LICENSE_ALLOW_HS256`: development/testing only. Keep `false` in production.
- `VARMOR_CLUSTER_UID`: optional override for cluster binding checks. If unset, the console reports the `kube-system` namespace UID as the runtime cluster UID.

When enforcement is enabled with `VARMOR_LICENSE_FAIL_OPEN=false`, a missing or
invalid license hides premium template packs and blocks policy-creation paths
that would add new protected workloads. Set fail-open only for development or
community-style evaluation builds.

## Runtime Usage And Limits

`GET /api/license` returns runtime usage:

- `usage.cluster_uid`
- `usage.nodes`
- `usage.policies`
- `usage.namespace_policies`
- `usage.cluster_policies`
- `limit_status`
- `warnings`
- `violations`

Supported license limits:

- `limits.max_nodes`: warns/marks non-compliant when node usage exceeds the signed limit.
- `limits.max_policies`: blocks direct policy create/import/restore/approve when the operation would exceed the signed limit.

A limit value of `0` means unlimited.

Cluster binding:

- If `payload.cluster_uid` is set and `VARMOR_CLUSTER_UID` is also set, they must match.
- If `VARMOR_CLUSTER_UID` is not set, the UI still displays the discovered `kube-system` namespace UID so operators can request a cluster-bound license.

Expiry behavior:

- `days_remaining <= 30` adds a warning.
- After `expires_at`, the license enters grace period if `grace_days > 0`.
- After grace period, the license becomes invalid.
