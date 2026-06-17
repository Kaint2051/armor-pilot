# vArmor Console Licensing

The console verifies signed JSON licenses. Keep the private key offline; the
product only needs the public key.

## Generate Signing Keys

```bash
python tools/license_tool.py gen-key \
  --private-key license-private.pem \
  --public-key license-public.pem
```

The command prints `VARMOR_LICENSE_PUBLIC_KEY`. Put that value in the
`varmor-console-secret` Kubernetes Secret.

## Sign a Customer License

```bash
python tools/license_tool.py sign \
  --private-key license-private.pem \
  --output customer-license.json \
  --license-id LIC-ACME-001 \
  --customer "ACME Corp" \
  --edition enterprise \
  --days 365 \
  --grace-days 7 \
  --features "templates:data_protection,templates:platform_infra,templates:incident_response" \
  --max-nodes 100 \
  --max-policies 500
```

Use `--features "*"` for a full enterprise license.

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
  --license customer-license.json
```

## Runtime Configuration

Set these environment variables in the console deployment:

- `VARMOR_LICENSE_PUBLIC_KEY`: base64 Ed25519 public key.
- `VARMOR_LICENSE_FILE`: path to the uploaded license file, default `/app/data/license.json`.
- `VARMOR_LICENSE_REQUIRED`: `true` to enforce licensed features.
- `VARMOR_LICENSE_FAIL_OPEN`: optional. Defaults to `false` when license is required, `true` otherwise.

When enforcement is enabled and the license is missing or invalid, premium
template packs are hidden. Existing core policy operations remain available.
See `docs/OPEN_CORE.md` for the Community/Enterprise edition split.
