# vArmor Console License Issuer Guide

This document is for the vendor or authorized license-issuing team. It contains
private signing-key operations and must not be distributed as customer
activation instructions.

Customer request and activation steps are documented in
[`LICENSING.md`](LICENSING.md).

## 1. Protect the Vendor Signing Key

Generate the Ed25519 signing key pair once:

```powershell
python tools/license_tool.py gen-key `
  --private-key license-private.pem `
  --public-key license-public.pem
```

Keep `license-private.pem` offline and backed up securely. Never place it in:

- Git.
- Product images.
- Customer clusters.
- CI logs or build artifacts.
- The web console.
- Shared chat, email, or ticket attachments.

Embed only the corresponding public key in the production console build.

## 2. Receive the Customer Request

The customer sends:

- `varmor-activation-request.json`
- Customer legal name.
- Purchased edition.
- Subscription period.
- Maximum nodes and policies.
- Contract or order reference.

Store the request with the order record. Do not accept only a copied
Installation ID for production licenses.

## 3. Verify the Activation Request

```powershell
python tools/license_tool.py verify-request `
  --request varmor-activation-request.json
```

Expected result:

```text
activation request signature ok
installation_id=vmi_...
cluster_uid=...
```

Reject the request if:

- Signature verification fails.
- Required identity fields are missing.
- Customer/order information does not match internal records.
- The Installation ID is already assigned to an incompatible active contract.

## 4. Create a Bound License Key

Example:

```powershell
python tools/license_tool.py sign `
  --private-key license-private.pem `
  --output customer-license.key `
  --activation-request varmor-activation-request.json `
  --license-id LIC-CUSTOMER-2026-001 `
  --customer "Customer Company" `
  --edition professional `
  --days 365 `
  --grace-days 14 `
  --features "*" `
  --max-nodes 50 `
  --max-policies 2000
```

The tool automatically copies `installation_id` and `cluster_uid` from the
verified activation request into the signed payload.

The output is one line:

```text
VARMOR1.<base64url-payload>.<ed25519-signature>
```

## 5. Verify Before Delivery

```powershell
python tools/license_tool.py verify `
  --public-key license-public.pem `
  --license customer-license.key
```

Expected result:

```text
license signature ok
```

Record:

- License ID.
- Customer.
- Edition.
- Installation ID.
- Cluster UID.
- Issue and expiration dates.
- Node and policy limits.
- Features.
- Contract/order reference.

## 6. Deliver the Key

Deliver only `customer-license.key` through the approved secure channel.

Tell the customer to follow [`LICENSING.md`](LICENSING.md):

1. Open **Users > License**.
2. Paste the complete `VARMOR1...` key.
3. Click **Save License**.
4. Confirm `Bound license: yes`.

Do not send:

- `license-private.pem`
- Internal license databases
- Another customer's activation request
- Another customer's license key

## 7. Editions and Features

Current feature flags include:

- `templates:data_protection`
- `templates:platform_infra`
- `templates:incident_response`
- `templates:*`
- `*`

Use `*` only for full-access or approved internal licenses.

Current signed limits:

- `limits.max_nodes`
- `limits.max_policies`

Edition names are commercial metadata. Ensure the features and limits in the
payload match the purchased edition.

## 8. Renewal

For renewal:

1. Request a fresh activation request from the same installation.
2. Verify the request.
3. Confirm the Installation ID matches the existing license record.
4. Issue a new key with a new License ID or revision and expiration date.
5. Verify and deliver the replacement key.

Do not extend expiration by editing an existing key. Any edit invalidates the
signature.

## 9. Rehost and Replacement

When a customer legitimately moves to another installation:

1. Receive the new activation request.
2. Verify it.
3. Locate the old License ID and contract.
4. Confirm authorization to rehost.
5. Mark the old installation/license as retired in internal records.
6. Issue a replacement key bound to the new Installation ID.

Without an activation server, retirement is enforced contractually and through
license records rather than real-time revocation.

## 10. Lost Installation Identity

If the customer loses `/app/data`, the console creates a new Installation ID.

Before issuing a replacement:

- Validate the customer identity.
- Validate the old License ID.
- Record the reason for replacement.
- Mark the previous installation as lost/retired.
- Issue a new key from the new activation request.

## 11. Trial and NFR Keys

Trial example:

```powershell
python tools/license_tool.py sign `
  --private-key license-private.pem `
  --output trial-license.key `
  --activation-request varmor-activation-request.json `
  --license-id TRIAL-CUSTOMER-001 `
  --customer "Customer Trial" `
  --edition trial `
  --days 30 `
  --grace-days 0 `
  --features "*" `
  --max-nodes 20 `
  --max-policies 500
```

NFR keys should use recognizable IDs:

```text
NFR-YYYY-NNN
```

## 12. Production Checklist

Before delivery:

- Activation request signature verified.
- Customer/order approved.
- License ID is unique.
- Edition, features, and limits match the order.
- Installation ID is present.
- Cluster UID is present.
- Expiration and grace period are correct.
- License signature verified.
- Private key remained offline.
- Issuance recorded internally.

