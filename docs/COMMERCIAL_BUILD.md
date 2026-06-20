# ArmorPilot Commercial Build

ArmorPilot uses separate Community and Enterprise container profiles.

## Security Boundaries

- Community builds physically remove Enterprise template payloads.
- Enterprise builds require a 32-byte Ed25519 public key at build time.
- Production builds disable runtime public-key replacement, HS256 licenses,
  and the built-in trial.
- Backend Python modules are compiled into native extension modules. Runtime
  images contain templates/static assets but no `.py` source files.
- Containers run as UID/GID `10001` with a read-only root filesystem.

Compilation raises the cost of reverse engineering but cannot make software
tamper-proof when the customer controls the host. Commercial protection must
also rely on private image delivery, signed licenses, updates, support, and
contract terms.

## Vendor Signing Key

Generate the Ed25519 signing key on a trusted offline machine:

```bash
python tools/license_tool.py gen-key \
  --private-key /secure/offline/armor-pilot-license-private.pem \
  --public-key /secure/offline/armor-pilot-license-public.pem
```

Never place the private key in Git, GitHub Actions, the container image,
Kubernetes, or the customer environment.

Convert only the raw public key to base64 and configure it as the GitHub Actions
secret `ARMORPILOT_LICENSE_PUBLIC_KEY_B64`. The release workflow injects that
public key into the compiled Enterprise verifier.

Rotating this key invalidates licenses signed by the previous key unless a
multi-key migration mechanism is added first.

## Local Build

Community:

```bash
docker build \
  --build-arg PRODUCT_EDITION=community \
  --build-arg BUILD_REVISION="$(git rev-parse HEAD)" \
  -t armor-pilot:community .
```

Enterprise:

```bash
docker build \
  --build-arg PRODUCT_EDITION=enterprise \
  --build-arg BUILD_REVISION="$(git rev-parse HEAD)" \
  --build-arg ARMORPILOT_LICENSE_PUBLIC_KEY_B64="${ARMORPILOT_LICENSE_PUBLIC_KEY_B64}" \
  -t armor-pilot:enterprise .
```

## Required Release Checks

Verify both images before delivery:

```bash
docker run --rm --entrypoint sh armor-pilot:community \
  -c 'test -z "$(find /app/app -type f -name "*.py" -print -quit)"'

docker run --rm --entrypoint sh armor-pilot:enterprise \
  -c 'test -z "$(find /app/app -type f -name "*.py" -print -quit)"'
```

Also confirm:

- Enterprise template identifiers are absent from the Community image.
- The image runs as UID `10001`.
- `/app` is not writable at runtime.
- A missing/invalid Enterprise license blocks licensed policy operations.
- A vendor-signed, installation-bound license succeeds.

## Trial Licenses

Production images do not support the old installation-date trial. Issue a
short-lived, installation-bound trial key through the normal Ed25519 signing
workflow instead.
