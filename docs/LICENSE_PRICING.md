# vArmor Console License and Pricing Guide

> Status: commercial proposal for internal review.
> Currency conversions are indicative. Final quotations should be issued in
> VND, exclude VAT, and define the exact support scope.
> Pricing strategy: penetration pricing, targeting approximately 50% below
> comparable enterprise Kubernetes security quotations for equivalent scope.
> Major vendors commonly use custom quotations, so this is a commercial target,
> not a guarantee against every competitor or negotiated deal.

## 1. Recommended Commercial Model

Use an annual on-premises subscription as the default commercial model.

- Primary billing metric: maximum Kubernetes worker/control-plane nodes managed.
- Secondary scope: maximum clusters covered by the subscription.
- Technical safety limit: maximum policies; do not use policy count as the main billing metric.
- License term: 12 months, with a 7-30 day grace period.
- License delivery: offline signed `VARMOR1...` key.
- Renewal: issue a new signed key with a new expiration date and limits.
- Customer environment: no outbound connection to a license server is required.

Node-based pricing is easier for customers to estimate than workload or policy
pricing. Policy and workload counts may change significantly during normal
operations, while node capacity is more stable and auditable.

## 2. Proposed Editions

### Community

Price: free.

Recommended scope:

- One cluster.
- Up to 5 nodes.
- Core policy creation and enforcement.
- Basic dashboard, logs, and policy status.
- Community template pack.
- Community support only.

Commercial purpose: product evaluation, labs, demonstrations, and community
adoption. Do not include premium template packs or guaranteed support.

### Trial

Price: free for 30 days.

Recommended scope:

- One cluster.
- Up to 20 nodes.
- Up to 500 policies.
- All product features and template packs.
- No production SLA.
- One trial per customer or organization.

The trial key should contain:

```text
edition=trial
days=30
grace_days=0
max_nodes=20
max_policies=500
features=*
```

### Starter

Proposed penetration price: **18,000,000 VND/year** (approximately **USD 700/year**).

Included:

- One production cluster.
- Up to 10 nodes.
- Up to 500 policies.
- Baseline and workload template packs.
- Policy backup and restore.
- Standard RBAC and review workflow.
- Email support during business hours.
- Two remote support sessions per year.

Additional node: **1,200,000 VND/node/year**.

Target customers: small businesses, private labs, small Kubernetes production
environments, and security teams starting runtime policy enforcement.

### Professional

Proposed penetration price: **60,000,000 VND/year** (approximately **USD 2,350/year**).

Included:

- Up to 3 production clusters.
- Up to 50 nodes in total.
- Up to 2,000 policies.
- All standard and premium template packs.
- Behavior model visualization and policy advisor.
- NetworkProxy builders and secret integration.
- Policy review workflow and custom roles.
- Backup/restore and audit reporting.
- Business-hours support with a next-business-day response target.
- Quarterly health check and template update package.

Additional node: **900,000 VND/node/year**.

Target customers: medium enterprises, managed private clouds, financial
technology teams, and organizations operating several Kubernetes environments.

### Enterprise

Proposed penetration price: **150,000,000 VND/year** (approximately **USD 5,900/year**).

Included:

- Up to 10 production clusters.
- Up to 200 nodes in total.
- Unlimited policies, subject to supported system capacity.
- All product features and template packs.
- Cluster-bound offline licenses.
- Custom compliance/template package.
- Priority support with a four-business-hour response target for critical cases.
- Quarterly upgrade assistance and security policy review.
- Up to 10 custom policy templates per year.
- Deployment and hardening documentation.

Additional node: **600,000 VND/node/year**.

Target customers: large enterprises, government, telecommunications, banking,
and regulated multi-cluster environments.

### Enterprise Plus

Price: custom quotation, recommended starting point **300,000,000 VND/year**.

Use this edition when the customer requires:

- More than 200 nodes or more than 10 clusters.
- Air-gapped deployment with controlled release packages.
- 24x7 support or a contractual SLA.
- Dedicated template development.
- Source escrow, OEM, reseller, or white-label rights.
- Custom integrations, reporting, or compliance mapping.
- Long-term support releases.

## 3. Pricing Formula

Recommended annual subscription formula:

```text
annual_price =
    edition_base_price
    + additional_nodes
    + premium_support
    + professional_services
    - approved_discount
```

Example for Professional with 70 nodes:

```text
Professional base, 50 nodes        60,000,000 VND
20 additional nodes                18,000,000 VND
Annual subscription total          78,000,000 VND
VAT                                calculated separately
```

Do not charge separately for every policy. Use `max_policies` as a capacity
guard based on the edition:

| Edition | Clusters | Included nodes | Policy limit |
|---|---:|---:|---:|
| Community | 1 | 5 | 100 |
| Trial | 1 | 20 | 500 |
| Starter | 1 | 10 | 500 |
| Professional | 3 | 50 | 2,000 |
| Enterprise | 10 | 200 | Unlimited |
| Enterprise Plus | Custom | Custom | Unlimited |

## 4. Optional Services

These services should be quoted separately from the software subscription:

| Service | Proposed price |
|---|---:|
| Installation and production hardening | 30,000,000-80,000,000 VND |
| Architecture/security assessment | 20,000,000-60,000,000 VND |
| Custom policy template | 5,000,000-15,000,000 VND/template |
| Custom integration | Quoted by scope |
| Administrator training, one day | 15,000,000-25,000,000 VND |
| On-site support | Travel cost plus daily professional-service rate |
| 24x7 premium support | Add 20%-35% of annual license price |

Implementation services should have a separate statement of work. Avoid hiding
unbounded customization inside the annual license price.

## 5. Discounts

Suggested maximum discounts:

- One-year subscription: list price.
- Two-year prepaid: up to 5%.
- Three-year prepaid: up to 10%.
- Education/non-profit: up to 20%, subject to approval.
- Reseller: 15%-25%, depending on who provides first-line support.
- Proof of concept: free or fixed fee; credit the fee against the purchase.

These prices already include a substantial market-entry discount. Avoid
discounts greater than 10% for direct annual deals without management approval.
Discount the service component only when the delivery scope is also reduced.

## 6. Perpetual License

A perpetual license may be offered only when procurement requires it.

Recommended structure:

```text
perpetual_license = 3.0 x annual_subscription_price
annual_maintenance = 20% of perpetual_license_price
```

Annual maintenance includes updates and support. If maintenance expires, the
customer may continue using the last licensed version but receives no new
features, templates, compatibility updates, or support.

Annual subscription is preferred because Kubernetes, kernels, container
runtimes, vArmor CRDs, and security rules change continuously.

## 7. License Key Types

### Evaluation Key

- Short expiration period.
- No grace period.
- Non-production terms.
- All features may be enabled for evaluation.

### Commercial Subscription Key

- 12-month expiration.
- 7-30 day grace period.
- Edition-specific features and limits.
- Optional cluster UID binding.

### NFR Key

Not For Resale keys are for internal demonstrations, partners, training, and
support environments. Use a recognizable customer and license ID:

```text
customer=Internal NFR
license_id=NFR-YYYY-NNN
edition=nfr
```

### Cluster-Bound Key

Use `cluster_uid` for higher-value production licenses. A copied key will fail
verification when the runtime cluster UID does not match.

Cluster binding should be optional during a proof of concept because customers
may rebuild evaluation clusters frequently.

## 8. License Key Generation

Generate the vendor signing key pair once:

```powershell
python tools/license_tool.py gen-key `
  --private-key license-private.pem `
  --public-key license-public.pem
```

Keep `license-private.pem` offline and backed up securely. Never place it in:

- The product image.
- The customer cluster.
- Git.
- CI logs or build artifacts.
- The web console.

Generate a Professional customer key:

```powershell
python tools/license_tool.py sign `
  --private-key license-private.pem `
  --output customer-license.key `
  --license-id LIC-CUSTOMER-2026-001 `
  --customer "Customer Company" `
  --edition professional `
  --days 365 `
  --grace-days 14 `
  --features "*" `
  --max-nodes 50 `
  --max-policies 2000 `
  --cluster-uid "<kube-system-namespace-uid>"
```

Verify before delivery:

```powershell
python tools/license_tool.py verify `
  --public-key license-public.pem `
  --license customer-license.key
```

The customer pastes the generated `VARMOR1...` line into **Install License**.

## 9. Renewal and Expiration Policy

Recommended timeline:

- 60 days before expiration: send renewal quotation.
- 30 days before expiration: show a warning in the console.
- Expiration date: enter the signed grace period.
- End of grace period: block creation/import/restore/approval of new policies.
- Existing policies in Kubernetes must not be automatically deleted.

Never automatically remove security policies because a commercial license
expired. Fail closed for new management operations while preserving the
customer's existing cluster protection.

## 10. Current Product Enforcement

The current signed payload supports:

- `edition`
- `features`
- `expires_at`
- `grace_days`
- `cluster_uid`
- `limits.max_nodes`
- `limits.max_policies`

Current runtime enforcement includes:

- Ed25519 signature verification.
- Expiration and grace-period validation.
- Optional cluster UID validation.
- Feature/template gating.
- Maximum-policy enforcement on create/import/restore/approval paths.
- Node and policy usage reporting.

Before publicly selling editions based on multiple clusters or support levels,
implement those commercial entitlements operationally or contractually. Do not
claim that the license key technically enforces a field that the product does
not yet enforce.

## 11. Quotation Checklist

Collect these values before issuing a quote:

- Legal customer name and tax information.
- Number of production and non-production clusters.
- Current node count and 12-month growth estimate.
- Air-gapped or internet-connected environment.
- Required support hours and response targets.
- Compliance requirements.
- Required custom templates/integrations.
- Subscription or perpetual procurement preference.
- Cluster UID if the license will be cluster-bound.

The quotation should state:

- Edition and included features.
- Maximum total nodes and clusters.
- Subscription dates.
- Grace period.
- Support scope.
- Upgrade entitlement.
- Professional services.
- Taxes, payment terms, and renewal terms.

## 12. Market Positioning Notes

Public vendor pages show that Kubernetes security products commonly combine a
free/evaluation entry point with enterprise packages that require a quotation.
There is no uniform public price standard across the category, so vArmor
Console pricing should be validated through initial customer pilots and adjusted
based on support effort and willingness to pay.

References checked on June 18, 2026:

- Sysdig pricing: https://www.sysdig.com/pricing
- Calico Cloud editions: https://www.calicocloud.io/
- Aqua Security pricing: https://www.aquasec.com/pricing/
