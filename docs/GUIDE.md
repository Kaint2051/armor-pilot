# ArmorPilot — Hướng Dẫn Sử Dụng Đầy Đủ

> **Phiên bản:** 1.0 | **Cập nhật:** 2026-05-13  
> **Hệ thống triển khai:** `http://172.30.2.129:8080`  
> **Thông tin đăng nhập mặc định:** `admin / Admin@ArmorPilot2026!`

---

## Mục lục

1. [Tổng quan hệ thống](#1-tổng-quan-hệ-thống)
2. [Kiến trúc](#2-kiến-trúc)
3. [Đăng nhập](#3-đăng-nhập)
4. [Giao diện Dashboard](#4-giao-diện-dashboard)
5. [Tạo VarmorPolicy — Hướng dẫn từng bước](#5-tạo-varmorpolicy)
6. [Quản lý Policy hiện có](#6-quản-lý-policy-hiện-có)
7. [Hiểu Audit Log](#7-hiểu-audit-log)
8. [API Reference (dành cho developer)](#8-api-reference)
9. [Khắc phục sự cố](#9-khắc-phục-sự-cố)
10. [Danh sách Lab Test](#10-danh-sách-lab-test)

---

## 1. Tổng quan hệ thống

**ArmorPilot** là giao diện đồ hoạ (Web GUI) quản trị bảo mật cho hệ thống **vArmor** — giải pháp sandbox container mã nguồn mở của ByteDance. Thay vì gõ lệnh `kubectl apply -f policy.yaml` thủ công, bạn có thể:

| Tác vụ | Không có Console | Có Console |
|---|---|---|
| Tạo policy bảo vệ | Viết YAML + kubectl apply | Click tạo trên giao diện |
| Xem trạng thái | kubectl get varmorpolicies | Bảng trực quan Ready/Pending |
| Kiểm tra Deployment | kubectl get deploy + xem label | Badge màu Protected/No Shield |
| Xóa policy | kubectl delete varmorpolicy | Nút Delete + xác nhận |
| Audit trail | Không có sẵn | Log tự động mọi thao tác |

### Các tính năng bảo mật tích hợp

- **Basic Authentication** với credential lưu trong Kubernetes Secret (không hardcode)
- **Audit Logging** chuẩn format, đẩy ra STDOUT để Fluentd/Loki thu thập
- **RBAC** tối thiểu hoá quyền hạn (Principle of Least Privilege)
- **Non-root container** chạy với UID 999
- **In-cluster config** tự động sử dụng ServiceAccount token

---

## 2. Kiến trúc

```
┌─────────────────────────────────────────────────────────────┐
│                    Trình duyệt / Browser                     │
│                  http://172.30.2.129:8080                    │
└────────────────────────────┬────────────────────────────────┘
                             │ HTTP
                             ▼
┌─────────────────────────────────────────────────────────────┐
│              systemd: armor-pilot-pf.service             │
│        kubectl port-forward 0.0.0.0:8080 → svc:80          │
└────────────────────────────┬────────────────────────────────┘
                             │ Kubernetes Service
                             ▼
┌─────────────────────────────────────────────────────────────┐
│           Kubernetes Service: armor-pilot-svc            │
│                   (NodePort 80:30080)                       │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│              Pod: armor-pilot (namespace: default)        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  gunicorn (2 workers) — port 5000                   │   │
│  │  Flask App (Python 3.12)                            │   │
│  │  ├─ auth.py       ← Basic Auth middleware           │   │
│  │  ├─ audit.py      ← Audit Logger → STDOUT           │   │
│  │  ├─ k8s_client.py ← In-cluster config               │   │
│  │  └─ routes/api.py ← REST API endpoints              │   │
│  └─────────────────────────────────────────────────────┘   │
│  ServiceAccount: armor-pilot-sa (ClusterRole bound)      │
└────────────────────────────┬────────────────────────────────┘
                             │ Kubernetes API
                             ▼
┌─────────────────────────────────────────────────────────────┐
│              Kubernetes API Server                           │
│  ├─ apps/deployments  (get, list, watch)                    │
│  └─ varmor.org/varmorpolicies (CRUD)                        │
└─────────────────────────────────────────────────────────────┘
```

### Luồng Xác thực

```
Browser → gửi Basic Auth header → Flask auth.py
               │
               ├─ Đúng credential → xử lý request
               └─ Sai/thiếu     → HTTP 401 Unauthorized
```

---

## 3. Đăng nhập

### Bước 1: Mở trình duyệt

Truy cập địa chỉ:
```
http://172.30.2.129:8080
```

### Bước 2: Nhập thông tin đăng nhập

| Trường | Giá trị |
|---|---|
| Username | `admin` |
| Password | `Admin@ArmorPilot2026!` |

Nhấn **Sign In**.

### Cơ chế hoạt động bên dưới

1. JavaScript mã hoá `username:password` thành chuỗi Base64
2. Gửi request `GET /api/namespaces/default/deployments` với header `Authorization: Basic <token>`
3. Nếu server trả về HTTP 200 → lưu token vào `localStorage` → hiện Dashboard
4. Nếu server trả về HTTP 401 → hiện thông báo lỗi

> **Lưu ý bảo mật:** Token được lưu trong `localStorage` của trình duyệt. Luôn đăng xuất (Logout) khi rời máy tính công cộng.

### Đăng xuất

Nhấn nút **Logout** ở góc phải trên cùng. Token bị xoá khỏi `localStorage`.

---

## 4. Giao diện Dashboard

Sau khi đăng nhập thành công, giao diện gồm 3 vùng chính:

```
┌─────────────────────────────────────────────────────────────┐
│ HEADER: [ArmorPilot]  [Namespace: default] [Load] [Logout]│
├───────────────────────────────────────┬─────────────────────┤
│                                       │                     │
│  FORM: Tạo VarmorPolicy mới          │   SIDEBAR:          │
│  ├─ Policy Name                       │   Deployments       │
│  ├─ Target Deployment (dropdown)      │   ├─ nginx  🛡️      │
│  ├─ Kernel Enforcers (checkboxes)     │   ├─ app    ⚠️      │
│  ├─ Defense Rules (checkboxes)        │   └─ api    ⚠️      │
│  ├─ Banned Files (textarea)           │                     │
│  └─ [Apply Policy]                    │                     │
│                                       │                     │
├───────────────────────────────────────┴─────────────────────┤
│  BẢNG: Active Policies                                       │
│  Name │ Target │ Mode │ Status │ Created │ Actions           │
│  ──────────────────────────────────────────────────────────  │
│  pol1 │ nginx  │ EP   │ Ready  │ 2026-05 │ [Delete]         │
└─────────────────────────────────────────────────────────────┘
```

### 4.1 Thanh Header

| Thành phần | Chức năng |
|---|---|
| `Namespace` input | Nhập namespace cần quản lý (mặc định: `default`) |
| `Load` button | Tải lại dữ liệu của namespace đã chọn |
| User badge | Hiển thị username đang đăng nhập |
| `Logout` | Đăng xuất, xoá session |

### 4.2 Sidebar — Danh sách Deployment

Hiển thị tất cả Deployment trong namespace đã chọn kèm trạng thái vArmor:

| Badge | Ý nghĩa | Điều kiện |
|---|---|---|
| 🛡️ **Protected** (xanh) | Deployment đã được vArmor bảo vệ | Label `sandbox.varmor.org/enable: "true"` tồn tại |
| ⚠️ **No Shield** (vàng) | Chưa có vArmor policy active | Không có label trên |

> Sidebar cũng cấp dữ liệu cho dropdown **Target Deployment** trong form tạo policy.

### 4.3 Bảng Active Policies

Hiển thị tất cả `VarmorPolicy` trong namespace:

| Cột | Ý nghĩa |
|---|---|
| Name | Tên policy (font mono màu xanh) |
| Target | Tên Deployment được bảo vệ |
| Mode | Chế độ bảo vệ (thường là `EnhancedProtect`) |
| Status | `Ready` (xanh) hoặc `Pending` (vàng) |
| Created | Ngày tạo |
| Actions | Nút Delete (có popup xác nhận) |

---

## 5. Tạo VarmorPolicy

### 5.1 Chuẩn bị

Trước khi tạo policy, đảm bảo:
1. Đã chọn đúng **Namespace** ở header và nhấn **Load**
2. Deployment cần bảo vệ đã xuất hiện trong sidebar
3. Đặt tên policy theo quy tắc: `<loại>-<tên-workload>` (ví dụ: `protect-nginx`)

### 5.2 Điền form tạo policy

#### Trường Policy Name
```
Quy tắc đặt tên: chỉ dùng chữ thường, số và dấu gạch ngang
Ví dụ: protect-nginx, sandbox-api-server, harden-frontend
```

#### Chọn Target Deployment
Chọn từ dropdown — chỉ hiển thị Deployment đang chạy trong namespace.

#### Kernel Enforcers — Chọn cơ chế thực thi

| Enforcer | Mô tả | Khi nào dùng |
|---|---|---|
| **AppArmor** | Profile AppArmor kernel-level | Đa số trường hợp, ổn định nhất |
| **Seccomp** | Lọc syscall (system call) | Kết hợp với AppArmor để tăng cường |
| **BPF** | eBPF-based enforcement | Kernel ≥ 5.10, linh hoạt nhất |
| **NetworkProxy** | Kiểm soát traffic mạng | Khi cần policy mạng |

> **Lưu ý:** Có thể chọn nhiều enforcer cùng lúc. Hệ thống kết hợp chúng (ví dụ `AppArmor|BPF`).

#### Built-in Defense Rules

| Rule | Mô tả | Cơ chế chặn |
|---|---|---|
| **Container Escape Prevention** | Ngăn kỹ thuật thoát container | Chặn ghi vào `core_pattern`, mount `securityfs`, ghi `release_agent` |
| **Privilege Escalation Prevention** | Ngăn leo thang đặc quyền | Chặn lạm dụng user namespace, disable capability nguy hiểm |

#### Banned File Paths — Đường dẫn file bị cấm

Mỗi dòng một đường dẫn. Container sẽ bị từ chối mọi quyền (read/write/exec/append) trên các file này.

```
# Ví dụ file nhạy cảm cần cấm:
/etc/shadow
/etc/passwd
/proc/sys/kernel/core_pattern
/proc/sysrq-trigger
/sys/kernel/debug
/var/run/docker.sock
```

### 5.3 Nhấn Apply Policy

Console sẽ:
1. Gửi POST request đến `/api/policies`
2. Backend dịch form data sang K8s CRD manifest
3. Gọi `CustomObjectsApi.create_namespaced_custom_object()`
4. Ghi Audit Log: `action=CREATE policy=<name> namespace=<ns> status=SUCCESS`
5. Hiện thông báo thành công màu xanh

### 5.4 Cấu trúc CRD được tạo ra

```yaml
apiVersion: varmor.org/v1beta1
kind: VarmorPolicy
metadata:
  name: protect-nginx
  namespace: default
spec:
  target:
    kind: Deployment
    name: nginx
  policy:
    enforcer: AppArmor|BPF
    mode: EnhancedProtect
    enhancedProtect:
      attackProtectionRules:
        - action: Deny
          rules:
            - disallow-write-core-pattern
            - disallow-mount-securityfs
            - disallow-write-release-agent
        - action: Deny
          rules:
            - disallow-abuse-user-ns
            - disable-cap-privilege
      fileRules:
        - path: /etc/shadow
          permissions: [read, write, exec, append]
        - path: /etc/passwd
          permissions: [read, write, exec, append]
```

---

## 6. Quản lý Policy hiện có

### Xem trạng thái policy

Bảng **Active Policies** tự động load sau khi nhấn **Load** hoặc sau khi tạo/xóa policy.

| Trạng thái | Ý nghĩa | Hành động |
|---|---|---|
| **Ready** (xanh) | Policy đã được vArmor agent áp dụng | Bình thường |
| **Pending** (vàng) | Policy đang chờ agent xử lý | Chờ hoặc kiểm tra varmor-agent |

### Xóa policy

1. Nhấn nút **Delete** trên hàng policy cần xóa
2. Popup xác nhận hiện ra với tên policy
3. Nhấn **Delete Policy** để xác nhận
4. System ghi Audit Log: `action=DELETE policy=<name> status=SUCCESS`
5. Bảng tự động refresh

> **Cảnh báo:** Xóa policy ngay lập tức gỡ bỏ bảo vệ khỏi Deployment tương ứng.

### Đổi Namespace

1. Nhập namespace mới vào ô **Namespace** trên header
2. Nhấn **Load**
3. Sidebar và bảng policy cập nhật theo namespace mới

---

## 7. Hiểu Audit Log

### 7.1 Xem Audit Log

```bash
# Lấy tên pod
kubectl get pods -l app=armor-pilot

# Xem log realtime
kubectl logs -f <pod-name>

# Chỉ xem AUDIT logs
kubectl logs <pod-name> | grep '\[AUDIT\]'
```

### 7.2 Format Audit Log

```
[TIMESTAMP] [AUDIT] user=<user> action=<action> policy=<name> namespace=<ns> status=<status> [details="<msg>"]
```

### 7.3 Ví dụ thực tế

```log
# Tạo policy thành công
[2026-05-13T15:30:00Z] [AUDIT] user=admin action=CREATE policy=protect-nginx namespace=default status=SUCCESS

# Xóa policy thành công
[2026-05-13T15:35:22Z] [AUDIT] user=admin action=DELETE policy=protect-nginx namespace=default status=SUCCESS

# Tạo thất bại (policy đã tồn tại)
[2026-05-13T15:36:01Z] [AUDIT] user=admin action=CREATE policy=protect-nginx namespace=default status=FAILURE details="Conflict"

# Xóa thất bại (policy không tồn tại)
[2026-05-13T15:40:00Z] [AUDIT] user=admin action=DELETE policy=old-policy namespace=default status=FAILURE details="Not Found"
```

### 7.4 Tích hợp với Fluentd / Loki

Vì log đẩy ra STDOUT theo chuẩn JSON-friendly, Fluentd/Loki tự thu thập:

```yaml
# Loki query để lọc audit events
{app="armor-pilot"} |= "[AUDIT]"

# Lọc theo action
{app="armor-pilot"} |= "[AUDIT]" |= "action=CREATE"

# Lọc failures
{app="armor-pilot"} |= "[AUDIT]" |= "status=FAILURE"
```

---

## 8. API Reference

Tất cả endpoints yêu cầu header `Authorization: Basic <base64(user:pass)>`.

### GET `/api/namespaces/<namespace>/deployments`

Lấy danh sách Deployment và trạng thái vArmor.

**Response:**
```json
{
  "deployments": [
    {
      "name": "nginx",
      "namespace": "default",
      "replicas": 3,
      "ready_replicas": 3,
      "varmor_enabled": true
    }
  ]
}
```

**Ví dụ curl:**
```bash
curl -s -u admin:Admin@ArmorPilot2026! \
  http://172.30.2.129:8080/api/namespaces/default/deployments | python3 -m json.tool
```

---

### GET `/api/namespaces/<namespace>/policies`

Lấy danh sách VarmorPolicy.

**Response:**
```json
{
  "policies": [
    {
      "name": "protect-nginx",
      "namespace": "default",
      "status": "Ready",
      "mode": "EnhancedProtect",
      "target": {"kind": "Deployment", "name": "nginx"},
      "created_at": "2026-05-13T15:00:00Z"
    }
  ]
}
```

---

### POST `/api/policies`

Tạo VarmorPolicy mới.

**Request body:**
```json
{
  "name": "protect-nginx",
  "namespace": "default",
  "target_deployment": "nginx",
  "enforcers": ["AppArmor", "BPF"],
  "rules": ["container_escape", "privilege_escalation"],
  "banned_files": ["/etc/shadow", "/etc/passwd"]
}
```

**Ví dụ curl:**
```bash
curl -s -u admin:Admin@ArmorPilot2026! \
  -X POST http://172.30.2.129:8080/api/policies \
  -H "Content-Type: application/json" \
  -d '{
    "name": "protect-nginx",
    "namespace": "default",
    "target_deployment": "nginx",
    "enforcers": ["AppArmor"],
    "rules": ["container_escape"],
    "banned_files": ["/etc/shadow"]
  }' | python3 -m json.tool
```

---

### DELETE `/api/namespaces/<namespace>/policies/<name>`

Xóa VarmorPolicy.

**Ví dụ curl:**
```bash
curl -s -u admin:Admin@ArmorPilot2026! \
  -X DELETE \
  http://172.30.2.129:8080/api/namespaces/default/policies/protect-nginx
```

---

## 9. Khắc phục sự cố

### Lỗi "Connection refused" khi truy cập web

```bash
# Kiểm tra port-forward service
systemctl status armor-pilot-pf

# Khởi động lại nếu cần
systemctl restart armor-pilot-pf

# Xem log
journalctl -u armor-pilot-pf -n 20
```

### Pod không khởi động được (CrashLoopBackOff)

```bash
kubectl describe pod -l app=armor-pilot
kubectl logs -l app=armor-pilot --previous
```

### Lỗi 401 dù nhập đúng password

```bash
# Kiểm tra secret
kubectl get secret armor-pilot-secret -o jsonpath='{.data.ADMIN_USER}' | base64 -d
kubectl get secret armor-pilot-secret -o jsonpath='{.data.ADMIN_PASS}' | base64 -d
```

### Policy tạo nhưng không chuyển sang Ready

```bash
# Kiểm tra varmor-agent
kubectl get pods -n varmor
kubectl logs -n varmor -l app=varmor-agent --tail=50
```

### Đổi password admin

```bash
# Xóa secret cũ và tạo mới
kubectl delete secret armor-pilot-secret
kubectl create secret generic armor-pilot-secret \
  --from-literal=ADMIN_USER=admin \
  --from-literal=ADMIN_PASS=NewStrongPassword!

# Restart pod để áp dụng
kubectl rollout restart deployment/armor-pilot
```

---

## 10. Danh sách Lab Test

| Lab | File | Mục tiêu kiểm tra |
|---|---|---|
| Lab 01 | `lab01_auth.sh` | Xác thực và bảo mật đăng nhập |
| Lab 02 | `lab02_deployments.sh` | Phát hiện Deployment và trạng thái vArmor |
| Lab 03 | `lab03_policies.sh` | Vòng đời Policy: Tạo → Kiểm tra → Xóa |
| Lab 04 | `lab04_banned_files.sh` | Kiểm tra chặn truy cập file nhạy cảm |
| Lab 05 | `lab05_escape_prevention.sh` | Kiểm tra ngăn Container Escape |
| Lab 06 | `lab06_audit_logs.sh` | Xác minh Audit Log đúng format |
| Lab 07 | `lab07_rbac.sh` | Xác minh phân quyền RBAC |
| ALL | `run_all_labs.sh` | Chạy toàn bộ 7 lab cùng lúc |

Chạy từng lab:
```bash
cd /opt/armor-pilot/labs
bash lab01_auth.sh
```

Chạy tất cả:
```bash
bash /opt/armor-pilot/labs/run_all_labs.sh
```
