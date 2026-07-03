# ArmorPilot — Deployment Guide

This guide covers every supported way to run ArmorPilot: as a Kubernetes
workload, as a standalone Linux service, as a standalone Windows
application, or from source for local development.

## Table of Contents

1. [Choosing a deployment method](#1-choosing-a-deployment-method)
2. [Prerequisites](#2-prerequisites)
3. [Method A — Kubernetes](#3-method-a--kubernetes)
4. [Method B — Linux (.deb + systemd)](#4-method-b--linux-deb--systemd)
5. [Method C — Windows (.exe)](#5-method-c--windows-exe)
6. [Method D — Local development](#6-method-d--local-development)
7. [Environment variables reference](#7-environment-variables-reference)
8. [Container images](#8-container-images)
9. [Migrating an existing installation](#9-migrating-an-existing-installation)
10. [Troubleshooting](#10-troubleshooting)
11. [Security notes](#11-security-notes)

---

## 1. Choosing a deployment method

| Method | Best for | Runs inside the cluster? |
|---|---|---|
| **A. Kubernetes** | Production clusters where the console should live alongside the workloads it protects | Yes |
| **B. Linux .deb** | A dedicated ops host / bastion outside the cluster (systemd service) | No — connects via kubeconfig |
| **C. Windows .exe** | A security engineer's workstation, or a Windows server outside the cluster | No — connects via kubeconfig |
| **D. Local dev** | Contributing to ArmorPilot itself | No |

All four methods produce the same application; they only differ in how the
Flask process is packaged, started, and supervised.

---

## 2. Prerequisites

- vArmor must already be installed on the target cluster, with its CRDs and
  agents ready (see the [vArmor installation guide](../../website/docs/getting_started/installation.md)).
- A kubeconfig with access to the cluster (only required if you want
  ArmorPilot to read/apply `VarmorPolicy` / `VarmorClusterPolicy`).
- An `ADMIN_PASS` of at least 12 characters — every deployment path refuses
  to start with a placeholder or short password.

---

## 3. Method A — Kubernetes

1. Confirm vArmor's CRDs and agents are ready:
   ```bash
   kubectl get crds | grep varmor
   kubectl get pods -n varmor-system
   ```
2. Pin the image tag/digest you want in `k8s/deployment.yaml`
   (`ghcr.io/kaint2051/armor-pilot-enterprise:<version>` or the community
   image — see [Container images](#8-container-images)). Avoid `latest` in
   production.
3. Create the private environment file:
   ```bash
   cp .env.example .env
   chmod 600 .env
   ```
4. Edit `.env` — set `ADMIN_USER` / `ADMIN_PASS` and review every other
   value (see [Environment variables reference](#7-environment-variables-reference)).
5. Deploy:
   ```bash
   ./scripts/deploy.sh .env          # Linux / macOS
   ```
   ```powershell
   .\scripts\deploy.ps1 -EnvFile .env   # Windows
   ```

What the script does:
- Rejects the env file if it still contains a placeholder (`REPLACE_WITH`,
  `changeme`, `abc@123`, …) or an `ADMIN_PASS` shorter than 12 characters.
- Creates/updates the Kubernetes Secret `armor-pilot-secret` from the env
  file (`kubectl create secret generic ... --from-env-file`).
- Applies `k8s/rbac.yaml` (ServiceAccount `armor-pilot-sa` + ClusterRole
  granting read/patch on Deployments/StatefulSets/DaemonSets, read on
  Pods/Namespaces/Nodes, get/list/create on Secrets, and full control of the
  `varmorpolicies` / `varmorclusterpolicies` / `armorprofilemodels` /
  `armorprofiles` CRDs) and `k8s/deployment.yaml`.
- Restarts the rollout and waits up to 180s for it to become ready.

What `k8s/deployment.yaml` sets up:
- Runs as non-root UID/GID `10001`, read-only root filesystem, all
  capabilities dropped, `seccompProfile: RuntimeDefault`.
- An init container `chown`s `/app/data` to `10001:10001` before the main
  container starts.
- `hostPath` volumes: `/var/log` → `/var/log-host` (AppArmor kernel log,
  read-only), `/var/log/varmor` → `/var/log-varmor` (violation log,
  read-only), `/var/lib/armor-pilot` → `/app/data` (SQLite DB, license,
  installation key — persists across pod restarts/reschedules on that
  node). `/tmp` is a 64Mi `emptyDir`.
- A `NodePort` Service (`armor-pilot-svc`) exposing port 30080 →
  container port 5000.

Access the console at `http://<any-node-ip>:30080` once the rollout
finishes.

---

## 4. Method B — Linux (.deb + systemd)

Use this when the console should run outside the cluster on its own Linux
host (bastion, ops VM), talking to Kubernetes only through a kubeconfig.

1. Get a `.deb`: download it from a
   [GitHub Release](https://github.com/Kaint2051/armor-pilot/releases), a
   CI artifact from `packages.yml`, or build it yourself:
   ```bash
   bash tools/build_deb.sh [VERSION]     # outputs dist/armor-pilot_<VERSION>_amd64.deb
   ```
2. Deploy:
   ```bash
   sudo bash tools/deploy_linux.sh                                    # auto-detect .deb + kubeconfig
   sudo bash tools/deploy_linux.sh armor-pilot_0.3.8_amd64.deb        # explicit .deb
   sudo bash tools/deploy_linux.sh armor-pilot_*.deb /etc/rancher/k3s/k3s.yaml
   ```

What the script does:
- Must be run as root. Installs the `.deb` (binary + systemd unit +
  `armor-pilot` service user + `/var/lib/armor-pilot` data dir via the
  package's `postinst`).
- Auto-detects a kubeconfig in this order: `/etc/rancher/k3s/k3s.yaml` →
  `/etc/rancher/rke2/rke2.yaml` → `/etc/kubernetes/admin.conf` →
  `/root/.kube/config` → `$HOME/.kube/config`; otherwise prompts for a
  path. Copies it to `/var/lib/armor-pilot/.kube/config` (mode `600`,
  owned by `armor-pilot:armor-pilot`) and writes `KUBECONFIG=...` into
  `/etc/armor-pilot/armor-pilot.env`.
- Warns if the kubeconfig's `server:` is `127.0.0.1`/`localhost` (the K3s
  default) — you'll need to `sed` it to the host's real IP if ArmorPilot
  will be reached from another machine.
- On first install only (no existing `users.db`), interactively prompts
  for the initial admin username/password (≥ 12 chars) and writes them to
  `/etc/armor-pilot/armor-pilot.env`.
- Enables and (re)starts the `armor-pilot.service` systemd unit.

Operating the service afterwards:
```bash
sudo systemctl status armor-pilot
sudo journalctl -u armor-pilot -f
sudo nano /etc/armor-pilot/armor-pilot.env   # edit config
sudo systemctl restart armor-pilot
sudo apt remove armor-pilot                  # or: sudo dpkg -r armor-pilot
```

Access the console at `http://<host-ip>:5000` (or whatever `PORT` is set
to in the env file).

---

## 5. Method C — Windows (.exe)

Use this for a Windows workstation or server outside the cluster.

```powershell
.\tools\deploy_windows.ps1
```

Common options (see `Get-Help .\tools\deploy_windows.ps1 -Full` for the
complete reference):

| Parameter | Default | Purpose |
|---|---|---|
| `-ExePath` | auto-detected next to the script, then `.\dist\ArmorPilot.exe` | Path to `ArmorPilot.exe` |
| `-InstallDir` | `C:\ArmorPilot` | Install location |
| `-KubeConfig` | `%USERPROFILE%\.kube\config` | Kubeconfig to copy in |
| `-Port` | `5000` | Listen port |
| `-BindHost` | `0.0.0.0` | Bind address |
| `-AutoStart` | off | Registers a Scheduled Task that runs as `SYSTEM` at boot (3 retries, 1 min apart) |
| `-Uninstall` | — | Removes the scheduled task and optionally deletes `-InstallDir` |

Examples:
```powershell
.\deploy_windows.ps1 -ExePath .\ArmorPilot.exe -AutoStart
.\deploy_windows.ps1 -Port 8080 -KubeConfig C:\k8s\config -AutoStart
.\deploy_windows.ps1 -Uninstall
```

What the script does: copies the exe into `-InstallDir`, copies the
kubeconfig, prompts for the initial admin username/password on first
install (stored in `ArmorPilot.env` next to the exe, ACL-restricted to the
current user), creates a desktop shortcut, and — with `-AutoStart` —
registers the boot-time Scheduled Task. At the end it offers to launch
ArmorPilot immediately.

Access the console at `http://localhost:<port>`.

---

## 6. Method D — Local development

```bash
pip install -r requirements.txt
npm install
npm run build:css
cp .env.example .env
# set ADMIN_USER and ADMIN_PASS in .env
flask --app app.main:app run --host 0.0.0.0 --port 5000
```

---

## 7. Environment variables reference

From `.env.example` — copy it to `.env` and fill in every value before any
deployment:

| Variable | Purpose |
|---|---|
| `ADMIN_USER` / `ADMIN_PASS` | Seed the first administrator account. Only takes effect while the user database is empty; rotate an existing password from the Access Control screen instead. |
| `DB_PATH` | Path to the SQLite user/audit database (default `/app/data/users.db`). |
| `APPARMOR_LOG_PATH` | Host path to the kernel AppArmor log (`kern.log`) mounted read-only into the container. |
| `VARMOR_VIOLATION_LOG_PATH` | Host path to vArmor's violation log, mounted read-only. |
| `ARMORPILOT_LICENSE_FILE` | Where the installed license document is stored. |
| `ARMORPILOT_LICENSE_REQUIRED` | Whether a valid license is required to use protected features. |
| `ARMORPILOT_LICENSE_FAIL_OPEN` | Whether license verification failures fail open (allow) or closed (deny). Keep `false` in production. |
| `ARMORPILOT_LICENSE_ALLOW_ENV_PUBLIC_KEY` / `ARMORPILOT_LICENSE_ALLOW_HS256` | Enable weaker/alternate license verification modes — leave `false` unless a vendor tells you otherwise. |
| `ARMORPILOT_LICENSE_REQUIRE_INSTALLATION_BINDING` | Require the license to be bound to this installation's identity. |
| `ARMORPILOT_INSTALLATION_KEY_FILE` / `ARMORPILOT_INSTALLATION_METADATA_FILE` | Installation identity private key and metadata — never share or commit these. |
| `ARMORPILOT_TRIAL_DAYS` | Trial length in source builds; `0` in production images (the built-in trial is compiled out). |

---

## 8. Container images

```text
ghcr.io/kaint2051/armor-pilot:<version>             # Community
ghcr.io/kaint2051/armor-pilot-enterprise:<version>  # Commercial
```

The Community image excludes Enterprise template payloads. The Enterprise
image compiles the Python backend into native extensions and ships no `.py`
source. Always pin a version tag or digest — never run `latest` in
production.

---

## 9. Migrating an existing installation

The `armor-pilot` rebrand changes Kubernetes resource names and the default
host data directory to `/var/lib/armor-pilot`. Before replacing an older
deployment:

1. Back up the old `/app/data` volume (user database, installation
   identity, installed license).
2. Restore it into the new ArmorPilot volume/data directory.
3. Deploy the new manifests/package and verify the Installation ID is
   unchanged.
4. Only remove the legacy Kubernetes resources once ArmorPilot is healthy
   on the new ones.

---

## 10. Troubleshooting

| Symptom | Check |
|---|---|
| Deploy script exits with "still contains an insecure placeholder" | `.env` still has `REPLACE_WITH` / `changeme` / `abc@123` — replace `ADMIN_PASS` with a real value. |
| systemd service won't start (Linux) | `sudo journalctl -u armor-pilot -n 40 --no-pager` |
| Console loads but policy/workload lists are empty | `KUBECONFIG` not set, or the kubeconfig's `server:` still points at `127.0.0.1` — see Method B. |
| Kubernetes rollout never finishes | `kubectl describe deployment/armor-pilot` / `kubectl logs` — usually a bad image tag or `armor-pilot-secret` missing required keys. |

---

## 11. Security notes

- Never commit `.env`, `data/`, `license-test/`, `*.key`, or `*.pem` — all
  are excluded in `.gitignore`. Keep the production `.env` outside the
  repository entirely, e.g. `sudo install -m 600 .env /etc/armor-pilot/armor-pilot.env`.
- `ADMIN_USER` / `ADMIN_PASS` only seed the very first account. Rotate it
  (and any other account's password) from the Access Control screen after
  first login, not by re-editing the env file.
- Production images run as UID/GID `10001` with a read-only root
  filesystem, writing only to `/app/data` and `/tmp`.
- The Kubernetes RBAC in `k8s/rbac.yaml` is cluster-scoped — review it
  against your own least-privilege requirements before granting it in a
  shared cluster.

See also: [System Overview](SYSTEM_OVERVIEW.md), [User Guide](USER_GUIDE.md),
[Licensing](LICENSING.md).
