# vArmor Console — User Guide

## Table of Contents
1. [Login](#1-login)
2. [Dashboard](#2-dashboard)
3. [Policy Management](#3-policy-management)
4. [Creating a New Policy — Step by Step](#4-creating-a-new-policy--step-by-step)
5. [Viewing and Editing a Policy](#5-viewing-and-editing-a-policy)
6. [Backup and Restore Policies](#6-backup-and-restore-policies)
7. [License Management](#7-license-management)
8. [User and Role Management](#8-user-and-role-management)
9. [Viewing Logs](#9-viewing-logs)
10. [Searching and Filtering Policies](#10-searching-and-filtering-policies)

---

## 1. Login

### Accessing the System
Open a browser and navigate to:
```
http://<server-address>:30080
```

### Default Credentials
| Account | Password | Access Level |
|---|---|---|
| `admin` | `Admin@varmor2024` | Full access |
| `operator1` | `pass1234` | Create & submit policies |

### Login Screen Fields

**Username**: Your account name (case-insensitive).

**Password**: Your password (case-sensitive, minimum 6 characters).

> After a successful login, the system automatically loads the Dashboard. Credentials are stored in the browser's `localStorage` — closing the tab does not log you out.

---

## 2. Dashboard

The Dashboard shows a high-level overview of the system state. Click the **Dashboard** tab in the navigation bar to access it.

### Stats Cards

| Card | Meaning |
|---|---|
| **Total Policies** | Total number of existing policies (namespace + cluster) |
| **NS Policies** | Number of VarmorPolicy objects (namespace-scoped) |
| **Cluster Policies** | Number of VarmorClusterPolicy objects (cluster-wide) |
| **Policies Active** | Number of policies currently in the Ready state (actively protecting) |

### Distribution Charts

**Policies by Mode**: Distribution of policies by security mode (EnhanceProtect, RuntimeDefault, etc.)

**Policies by Enforcer**: Distribution by enforcement engine (AppArmor, BPF, Seccomp)

### License Status (top-right header)
Shows the current license state. Green = valid, yellow = expiring soon / in grace period, red = attention required.

---

## 3. Policy Management

Click the **Policy** tab in the navigation bar to enter the policy management section.

### Policy List Interface

#### Search and Filter Bar
- **Search box**: Type to search by policy name, target name, mode, or enforcer.
- **All Scope**: Filter by scope — `Namespace` (namespace policy) or `Cluster` (cluster-wide policy).
- **All Mode**: Filter by security mode.
- **All Status**: Filter by status — `Ready` (running), `Pending` (processing), `Error` (has errors).

> When a filter is active, the dropdown highlights in blue to indicate it is in use.

#### Policy Table

| Column | Meaning |
|---|---|
| ☐ (checkbox) | Select multiple policies for bulk deletion |
| **Name** | Policy name (blue, monospace font) |
| **Scope** | `NS` (namespace) or `Cluster` (cluster-wide) |
| **Target** | Workload name or `selector` if using label selection |
| **Mode** | Active security mode |
| **Enforcer** | Enforcement engine (AppArmor / BPF / Seccomp) |
| **Status** | State: `Ready` (green), `Pending` (yellow), error (red) |
| **Created** | Policy creation date |
| **Actions** | ✏️ Edit \| View \| ⬇ Export \| Del |

#### Pagination
- Each page displays **10 policies**.
- Use **← Prev / Next →** buttons or page numbers to navigate.
- Current page information is shown as: `Page 1/3 (25 policies)`.

---

## 4. Creating a New Policy — Step by Step

Click the **+ New Policy** button to open the policy creation wizard.

---

### Step 1: Target (Workload to Protect)

#### Namespace
**Meaning**: The Kubernetes namespace where the workload is running.
**Example**: `default`, `production`, `monitoring`
> Only applies when creating a **Namespace Policy**. Cluster Policies ignore this field.

#### Scope
| Value | Meaning |
|---|---|
| **Namespace** | Creates a `VarmorPolicy` — applies within the specified namespace |
| **Cluster** | Creates a `VarmorClusterPolicy` — applies across the entire cluster |

> Cluster Policies require the `policies:apply_direct` permission and are typically used for system workloads.

#### Target Kind
The type of workload to protect:

| Kind | Description |
|---|---|
| **Deployment** | The most common stateless application (web servers, APIs) |
| **StatefulSet** | Stateful applications (databases, message queues) |
| **DaemonSet** | Runs on every node (log agents, monitoring) |
| **Pod** | A standalone Pod not managed by a controller |

#### Target Selection — By Name
**Target Name**: Enter the exact name of the Deployment / StatefulSet / DaemonSet / Pod.

> The dropdown will automatically load workloads available in the selected namespace.

#### Target Selection — By Label Selector
Use this when you want to apply a policy to multiple workloads at once based on labels.

**matchLabels**: Key-value pairs that must all match exactly.
```
app = nginx
env = production
```

**matchExpressions**: More flexible conditions.

| Operator | Meaning | Example |
|---|---|---|
| `In` | Value must be one of the listed set | `tier In [frontend, backend]` |
| `NotIn` | Value must not be in the listed set | `env NotIn [dev, test]` |
| `Exists` | Key must exist (no value needed) | `app Exists` |
| `DoesNotExist` | Key must not exist | `debug DoesNotExist` |

---

### Step 2: Policy (Security Mode)

#### Policy Name
**Meaning**: A unique identifier for the policy within the namespace / cluster.
**Rules**: Use only lowercase letters, numbers, and hyphens (`-`). Do not use dots, underscores, or spaces.
**Example**: `protect-nginx`, `harden-payment-api`, `secure-database`

> Once created, the policy name **cannot be changed**. You must delete and recreate the policy to rename it.

#### Mode (Security Mode)

Choose one of 5 modes:

| Mode | Protection Level | Use When |
|---|---|---|
| **AlwaysAllow** | None | Debugging, testing |
| **RuntimeDefault** | Low — baseline | General workloads |
| **EnhanceProtect** | Medium–High | Production, requiring advanced protection |
| **BehaviorModeling** | Observe only | Learning phase |
| **DefenseInDepth** | Highest | After a behavioral model has been built |

#### Enforcer (Enforcement Engine)

Select one or more engines. Combinations are supported:

| Engine | Protects | Requirements |
|---|---|---|
| **AppArmor** | Files, capabilities, network | AppArmor kernel module |
| **BPF** | Syscalls, files, network, processes | Kernel ≥ 5.10, BTF |
| **Seccomp** | Syscall filtering | Kernel ≥ 3.17 |
| **NetworkProxy** | Egress network control | BPF must be available |

> If a node does not support the selected engine, the policy will enter an **Error** state.

---

### Step 3: Rules (Security Rules)

Only applicable when the **EnhanceProtect** mode is selected.

#### 3.1 Hardening Rules (Lock Down System Weaknesses)

Select from the list of built-in rules. Each rule blocks a specific attack vector.

| Rule | Protects Against |
|---|---|
| `disable-cap-all` | Removes all Linux capabilities (strongest option) |
| `disable-cap-privileged` | Removes dangerous capabilities (CAP_SYS_ADMIN, etc.) |
| `disable-cap-all-except-net-bind-service` | Retains only the port-binding capability |
| `disallow-mount` | Blocks filesystem mounting |
| `disallow-insmod` | Blocks loading kernel modules |
| `disallow-load-bpf-prog` | Blocks loading eBPF programs |
| `disallow-write-core-pattern` | Prevents writes to /proc/sys/kernel/core_pattern |
| `disallow-mount-procfs` | Prevents mounting /proc |
| `disallow-create-user-ns` | Prevents creating user namespaces (blocks container escapes) |
| `disallow-abuse-user-ns` | Prevents abusing user namespaces |
| `disallow-access-procfs-root` | Prevents access to /proc/[pid]/root |
| `disallow-access-kallsyms` | Prevents reading /proc/kallsyms (exposes kernel addresses) |
| `disallow-debug-disk-device` | Prevents raw disk device access |

#### 3.2 Attack Protection Rules (Block Post-Intrusion Techniques)

Blocks attack techniques once an attacker has gained access to a container.

**Block dangerous tools inside the container**:
| Rule | Effect |
|---|---|
| `disable-shell` | Blocks bash, sh, zsh, dash (prevents RCE via shell) |
| `disable-wget` | Blocks wget (prevents payload downloads) |
| `disable-curl` | Blocks curl |
| `disable-chmod` | Blocks chmod (prevents changing file permissions) |
| `disable-su-sudo` | Blocks su/sudo (prevents privilege escalation) |
| `disable-busybox` | Blocks busybox (an attacker's Swiss Army knife) |

**Block access to sensitive information**:
| Rule | Effect |
|---|---|
| `disable-write-etc` | Prevents writes to /etc (e.g., modifying hosts, passwd) |
| `disable-access-passwd` | Prevents reading /etc/passwd |
| `disable-access-shadow` | Prevents reading /etc/shadow (password hashes) |
| `disable-access-ssh-dir` | Prevents reading ~/.ssh (private keys) |
| `mitigate-sa-leak` | Prevents reading the ServiceAccount token (Kubernetes credentials) |
| `mitigate-host-ip-leak` | Prevents leaking the host node IP |

**Block cloud metadata access**:
| Rule | Cloud Provider |
|---|---|
| `block-access-to-metadata-service` | Generic (169.254.169.254) |
| `block-access-to-aws-metadata-service` | AWS EC2 |
| `block-access-to-alibaba-metadata-service` | Alibaba Cloud |
| `block-access-to-oci-metadata-service` | Oracle Cloud |

**Network control**:
| Rule | Effect |
|---|---|
| `disable-network` | Blocks all network traffic |
| `disable-inet` | Blocks IPv4 and IPv6 |
| `disable-ipv4` / `disable-inet` | Blocks IPv4 |
| `disable-ipv6` / `disable-inet6` | Blocks IPv6 |
| `disable-tcp` | Blocks TCP |
| `disable-udp` | Blocks UDP |
| `disable-icmp` | Blocks ICMP (ping) |
| `block-access-to-kube-apiserver` | Blocks access to the Kubernetes API server |
| `block-access-to-container-runtime` | Blocks the container runtime socket (prevents Docker escape) |

#### 3.3 Vulnerability Mitigation Rules (Patch Known CVEs)

| Rule | CVE | Description |
|---|---|---|
| `dirty-pipe-mitigation` | CVE-2022-0847 | Dirty Pipe — write to read-only files |
| `runc-override-mitigation` | CVE-2019-5736 | runc override — container escape |
| `cgroups-lxcfs-escape-mitigation` | — | Container escape via cgroups/lxcfs |
| `ingress-nightmare-mitigation` | CVE-2025-1974 | IngressNightmare — RCE via ingress |
| `copy-fail-mitigation` | — | Copy-related container bug |

#### 3.4 AppArmor Raw Rules
Enter AppArmor profile rules directly for fine-grained control:
```
/etc/nginx/nginx.conf r,
/var/log/nginx/ rw,
```

#### 3.5 BPF Raw Rules
Configure eBPF rules directly when special-case control is needed.

#### 3.6 Seccomp Rules
Specify the list of syscalls to allow or block.

**Syscall Actions**:
| Action | Meaning |
|---|---|
| `SCMP_ACT_KILL` | Kill the process immediately when this syscall is invoked |
| `SCMP_ACT_ERRNO` | Return an error (EPERM) — process continues running |
| `SCMP_ACT_LOG` | Log the call but allow it |
| `SCMP_ACT_ALLOW` | Allow unconditionally |

---

### Step 4: Review (Review Before Applying)

Review the full configuration before creating the policy.

#### Validate Button
Checks the syntax and validity of the policy. Validation must succeed before you can apply.

**Validation Results**:
- ✅ **Valid**: Policy is correct and ready to apply.
- ❌ **Invalid**: There are syntax errors — see the error message below.

#### Apply Button (Admin Only)
Applies the policy directly to the cluster. The policy appears in the list immediately.

#### Submit for Review Button (Operator)
Sends the policy to a queue awaiting Admin approval. The admin will see it in the Review tab.

---

## 5. Viewing and Editing a Policy

### View Policy Details
Click the **View** button in the Actions column to see the full CRD YAML for the policy.

### Edit a Policy
Click the **✏️ (Edit)** button to reopen the wizard with the existing configuration pre-filled.

> The following fields **cannot be changed**: **policy name**, **scope** (namespace/cluster), **namespace**.

### Export a Policy
Click the **⬇** button to download the YAML file for the policy.

### Delete a Policy
Click **Del** → confirm the dialog → the policy is removed from the cluster.

> Deleting a policy **immediately stops protection** for the targeted workload.

### Bulk Delete
Tick the checkboxes for multiple policies → the **Delete Selected** button appears → confirm to delete all selected policies.

---

## 6. Backup and Restore Policies

### Backup
Click the **⬇ Backup** button on the toolbar.

**Options**:
- ☑ **Namespace policies**: Back up VarmorPolicy objects in the current namespace.
- ☑ **Cluster policies**: Back up VarmorClusterPolicy objects.

The backup file is a JSON array containing the spec of all policies — runtime fields such as status, uid, and resourceVersion are excluded.

### Restore

Click the **↺ Restore** button to open the restore panel.

**Step 1**: Select the JSON backup file downloaded previously.

**Step 2**: Choose how to handle policies that already exist:

| Mode | Behavior |
|---|---|
| **Skip existing** | Skip policies that already exist; only create new ones |
| **Overwrite existing** | Overwrite existing policies with the version from the backup |

**Step 3**:
- **Restore Directly** (Admin): Apply immediately without requiring approval.
- **Submit for Review** (Operator): Send to the approval queue.

---

## 7. License Management

Click the **Users/Access Control** tab → select **License** in the left sub-menu.

### 7.1 Viewing License Status

**License Status Card** displays:

| Field | Meaning |
|---|---|
| **Status** | trial / valid / in_grace / missing / invalid |
| **Edition** | trial / starter / enterprise |
| **Customer** | Customer name recorded in the license |
| **License ID** | License identifier (e.g., LIC-VNNIC-001) |
| **Issued At** | Issue date |
| **Expires At** | Expiry date |
| **Days Remaining** | Number of days left |
| **Grace Days** | Number of grace days after expiry |
| **Installation ID** | Installation identifier (`vmi_...`) |
| **Cluster UID** | UID of the kube-system namespace |
| **Max Nodes** | Node limit (0 = unlimited) |
| **Max Policies** | Policy limit (0 = unlimited) |
| **Features** | `["*"]` = all features enabled |

### 7.2 Downloading an Activation Request

When you need to request a license from the vendor:

1. Click **Download Activation Request**.
2. Fill in the contact information:

| Field | Required | Meaning |
|---|---|---|
| **Full Name** | ✅ | Contact person |
| **Company / Organization** | ✅ | Name of the organization |
| **Contact Email** | ✅ | Email address to receive the license |
| **Phone Number** | ❌ | Contact phone number |

3. Fill in the license request details:

| Field | Meaning |
|---|---|
| **Edition** | `Enterprise` (full) / `Starter` / `Trial` |
| **Duration** | 1 year / 2 years / 3 months / 30 days / Custom |
| **Max nodes** | Maximum number of nodes required (0 = unlimited) |
| **Max policies** | Maximum number of policies required (0 = unlimited) |
| **Notes** | Additional details about the environment or intended use |

4. Click **Download** — the file `varmor-activation-request.json` is saved.
5. Send this file to the vendor.

### 7.3 Entering a License Key

After receiving a license from the vendor (format: `VARMOR1.xxx.yyy`):

1. Paste the license string into the **License Key** field.
2. Click **Save License**.
3. The system verifies and updates the license status immediately.

**Common Errors**:

| Error | Cause |
|---|---|
| `invalid signature` | License was modified or signed with a wrong key |
| `installation_id mismatch` | License is bound to a different installation |
| `license has expired` | License has expired and the grace period is over |
| `license key string is required` | The input field is empty |

### 7.4 Removing a License

Click **Remove License** (red button) → confirm → the license is deleted. The system returns to an unactivated state (if the trial has also expired, it enters a locked state).

### 7.5 Creating a License (For Vendors)

Vendors use the CLI tool on a machine that holds the private key:

```powershell
cd varmor-console

python tools/license_tool.py sign `
  --private-key license-test/test-license-private.pem `
  --activation-request path\to\varmor-activation-request.json `
  --license-id LIC-CUSTOMER-001 `
  --customer "Customer Name" `
  --edition enterprise `
  --days 365 `
  --output customer-license.key
```

**Full Parameter Reference**:

| Parameter | Required | Meaning |
|---|---|---|
| `--private-key` | ✅ | Path to the vendor Ed25519 private key PEM file |
| `--activation-request` | ✅ | Customer's activation request JSON file |
| `--license-id` | ✅ | License identifier (e.g., LIC-VNNIC-001) |
| `--customer` | ✅ | Customer name |
| `--edition` | ❌ | trial / starter / enterprise (default: enterprise) |
| `--days` | ❌ | Validity period in days (default: 365) |
| `--grace-days` | ❌ | Grace days after expiry (default: 14) |
| `--max-nodes` | ❌ | Node limit (0 = unlimited) |
| `--max-policies` | ❌ | Policy limit (0 = unlimited) |
| `--features` | ❌ | Features: `*` or a comma-separated list |
| `--output` | ❌ | Output file (default: print to screen) |

---

## 8. User and Role Management

Click the **Users/Access Control** tab → select **Users** in the left sub-menu.

> Only the **admin** account can see this section.

### 8.1 User List

The table shows all accounts in the system:

| Column | Meaning |
|---|---|
| **Username** | Login name |
| **Role** | Role: `admin` / `operator` / `viewer` or a custom role |
| **Created** | Account creation date |
| **Actions** | Change password \| Change role \| Delete |

### 8.2 Creating a New User

Click **+ New User**.

| Field | Meaning |
|---|---|
| **Username** | Login name, must be unique in the system |
| **Password** | Password (minimum 6 characters) |
| **Role** | Initial role for the user |

### 8.3 Built-in Roles

| Role | Summary |
|---|---|
| **admin** | Full access — create/edit/delete/apply policies, manage users and licenses |
| **operator** | Create and submit policies for admin approval; view logs and models |
| **viewer** | Read-only — cannot create, edit, or delete anything |

### 8.4 Custom Roles

Click **Roles** in the sub-menu to view and manage custom roles.

You can create a role with any combination of the 26 available permissions. For example, create a `log-analyst` role with only `logs:view` + `logs:violations` + `logs:apparmor`.

### 8.5 Changing Passwords

- **Change your own password**: Go to your profile → Change Password.
- **Admin resets another user's password**: Click the key icon next to the user's name.

---

## 9. Viewing Logs

Click the **Logs** tab in the navigation bar.

### 9.1 Security Events (Security Violations)

Displays events blocked by policies (AppArmor denials, BPF blocks).

| Column | Meaning |
|---|---|
| **Time** | When the event occurred |
| **Namespace** | Namespace of the pod |
| **Pod** | Name of the pod that generated the event |
| **Profile** | AppArmor profile applied at the time |
| **Operation** | The blocked action (exec, open, connect, etc.) |
| **Denied** | The resource that was blocked (file path, network address) |
| **Severity** | Severity level |

Click an event to view details and remediation suggestions.

### 9.2 Audit Trail

Records every action performed in the console (who did what, when, and the outcome).

| Column | Meaning |
|---|---|
| **Time** | When the action was performed |
| **User** | Account that performed the action |
| **Action** | Action type: CREATE_POLICY, DELETE_USER, UPDATE_LICENSE, etc. |
| **Resource** | Type of resource affected |
| **Target** | Specific name of the resource |
| **Result** | SUCCESS / FAILURE |
| **Detail** | Additional details |

### 9.3 AppArmor Profiles

Shows the status of AppArmor profiles currently loaded on nodes.

| State | Meaning |
|---|---|
| **loaded** | Profile is active on the node |
| **unloaded** | Profile is not / no longer loaded |

---

## 10. Searching and Filtering Policies

### Search (Keyword Search)
Type in the search box to find policies by:
- Policy name
- Target workload name
- Mode name
- Enforcer name
- Scope

### Filter Scope
| Value | Shows |
|---|---|
| All Scope | All policies |
| Namespace | Only VarmorPolicy (namespace-scoped) |
| Cluster | Only VarmorClusterPolicy |

### Filter Mode
Select a specific mode to show only policies using that mode.

### Filter Status
| Value | Shows |
|---|---|
| All Status | All policies |
| Ready | Only policies that are running normally |
| Pending | Policies being processed (newly created or updating) |
| Error | Policies with errors (node doesn't support enforcer, invalid spec, etc.) |

> All filters work together and combine with the search input simultaneously.
> When a filter is active, the dropdown turns blue for easy identification.

---

## Appendix: Policy Status Explained

| Status | Phase | Meaning | Action Required |
|---|---|---|---|
| Ready | Protecting | Policy is actively protecting the workload | None |
| Pending | Pending | Being created or updated | Wait |
| Pending | Modeling | BehaviorModeling is running | Wait for completion |
| Pending | Completed | Modeling finished, waiting to apply | Apply DefenseInDepth |
| Error | Error | Error preventing policy application | View details → fix |
| Error | Failed | Failed to load the profile | Check node logs |

## Appendix: Tips and Shortcuts

- **Ctrl+Shift+R**: Hard reload the page, clearing the browser cache — use this if you don't see the latest changes.
- **Refresh button** (↺) on the policy table: Reloads the list from Kubernetes without reloading the whole page.
- **Select All**: Tick the header checkbox to select all policies visible on the current page.
- **Export YAML**: Click ⬇ to download the YAML for a policy — useful for backup or manual application via `kubectl`.
