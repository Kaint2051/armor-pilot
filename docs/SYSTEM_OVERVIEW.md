# vArmor Console — Tổng quan hệ thống

## 1. Giới thiệu

**vArmor** là hệ thống bảo mật container (Cloud-Native Runtime Security) chạy trên Kubernetes. vArmor Console là giao diện quản trị web cho phép tạo, quản lý và giám sát các **Policy bảo mật** áp dụng trực tiếp lên workload (Deployment, StatefulSet, DaemonSet, Pod) trong cluster.

Hệ thống hoạt động theo mô hình **eBPF + LSM** (Linux Security Module), can thiệp ở tầng kernel để ngăn chặn hành vi nguy hiểm mà không cần thay đổi container image hay cấu hình ứng dụng.

---

## 2. Kiến trúc hệ thống

```
┌─────────────────────────────────────────────────────┐
│                   vArmor Console                     │
│            (Web UI - Python/Flask)                   │
│         Giao diện quản trị: port 30080               │
└────────────────────┬────────────────────────────────┘
                     │ REST API
┌────────────────────▼────────────────────────────────┐
│              Kubernetes API Server                   │
│         (VarmorPolicy / VarmorClusterPolicy CRD)     │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│              vArmor Agent (DaemonSet)                │
│    Chạy trên mỗi node, áp dụng policy vào kernel    │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│           Enforcement Engines                        │
│    AppArmor  │  BPF/eBPF  │  Seccomp  │  NetworkProxy│
└─────────────────────────────────────────────────────┘
```

### Thành phần chính

| Thành phần | Mô tả |
|---|---|
| **vArmor Console** | Web UI quản trị, REST API server |
| **vArmor Manager** | Controller xử lý CRD VarmorPolicy/VarmorClusterPolicy |
| **vArmor Agent** | DaemonSet chạy trên mỗi node, nhận lệnh từ Manager |
| **Enforcement Engines** | AppArmor, BPF, Seccomp, NetworkProxy — tầng thực thi |
| **Database (SQLite)** | Lưu users, roles, audit log nội bộ console |
| **PVC Storage** | Lưu license, installation key, behavior models |

---

## 3. Các chế độ Policy (Policy Modes)

### 3.1 AlwaysAllow
- **Mục đích**: Không áp dụng bất kỳ hạn chế nào.
- **Dùng khi**: Tắt bảo vệ tạm thời để debug, hoặc đánh dấu workload tin tưởng hoàn toàn.
- **Rủi ro**: Cao — container có toàn quyền.

### 3.2 RuntimeDefault
- **Mục đích**: Áp dụng profile bảo mật mặc định của container runtime (containerd/Docker).
- **Dùng khi**: Baseline bảo mật tối thiểu cho workload thông thường.
- **Đặc điểm**: Chặn các syscall nguy hiểm phổ biến, không cần cấu hình thêm.

### 3.3 EnhanceProtect ⭐ (phổ biến nhất)
- **Mục đích**: Bảo vệ chủ động dựa trên luật (rule-based) với ba lớp:
  - **Hardening Rules**: Khóa các điểm yếu hệ thống (mount, insmod, capabilities)
  - **Attack Protection Rules**: Chặn kỹ thuật tấn công sau khi xâm nhập (shell, wget, metadata service)
  - **Vulnerability Mitigation Rules**: Vá các CVE đã biết (Dirty Pipe, runc override, v.v.)
- **Dùng khi**: Môi trường production cần bảo vệ nâng cao.
- **Enforcers hỗ trợ**: AppArmor, BPF, Seccomp, NetworkProxy.

### 3.4 BehaviorModeling
- **Mục đích**: Quan sát và ghi lại hành vi thực tế của workload (learning mode).
- **Dùng khi**: Giai đoạn đầu — để hệ thống tự học profile trước khi áp dụng bảo vệ.
- **Luồng**: BehaviorModeling → (hoàn thành) → DefenseInDepth
- **Chú ý**: Trong khi modeling, workload không bị hạn chế.

### 3.5 DefenseInDepth
- **Mục đích**: Allowlist nghiêm ngặt — chỉ cho phép đúng những hành vi đã được model.
- **Dùng khi**: Sau khi hoàn thành BehaviorModeling, áp profile đã học.
- **Đặc điểm**: Mạnh nhất, nhưng dễ gây lỗi nếu profile không đầy đủ.

---

## 4. Enforcement Engines

### 4.1 AppArmor
- **Tầng**: LSM (Linux Security Module) trong kernel.
- **Kiểm soát**: File system access, capabilities, network, mount.
- **Yêu cầu**: Kernel có AppArmor enabled (Ubuntu, Debian mặc định có).
- **Profile**: Dạng text rule, áp trực tiếp vào kernel.

### 4.2 BPF (eBPF)
- **Tầng**: eBPF programs hook vào kernel events.
- **Kiểm soát**: Syscall-level, network, file, process.
- **Yêu cầu**: Kernel ≥ 5.10, BTF enabled, CAP_SYS_ADMIN.
- **Ưu điểm**: Linh hoạt hơn AppArmor, hỗ trợ NetworkProxy.

### 4.3 Seccomp
- **Tầng**: Syscall filter ở tầng process.
- **Kiểm soát**: Danh sách syscall được phép/bị chặn.
- **Yêu cầu**: Kernel ≥ 3.17 (hầu hết distro hiện đại).
- **Hành động**: SCMP_ACT_KILL, SCMP_ACT_ERRNO, SCMP_ACT_LOG, SCMP_ACT_ALLOW.

### 4.4 NetworkProxy
- **Tầng**: Transparent proxy cho network traffic.
- **Kiểm soát**: Egress traffic theo domain/IP/port.
- **Yêu cầu**: BPF engine phải available.
- **Dùng khi**: Cần kiểm soát kết nối ra ngoài của container.

### Bảng kết hợp Enforcer hợp lệ

| Kết hợp | Ghi chú |
|---|---|
| AppArmor | Cơ bản nhất |
| BPF | Mạnh hơn AppArmor |
| Seccomp | Lọc syscall |
| AppArmor + BPF | Kết hợp file + syscall |
| AppArmor + Seccomp | Phổ biến cho production |
| BPF + Seccomp | eBPF + syscall filter |
| BPF + NetworkProxy | Network control |
| AppArmor + BPF + Seccomp | Bảo vệ toàn diện |

---

## 5. Policy Scope (Phạm vi áp dụng)

| Scope | CRD | Áp dụng cho |
|---|---|---|
| **Namespace** | `VarmorPolicy` | Workload trong một namespace cụ thể |
| **Cluster** | `VarmorClusterPolicy` | Workload trong bất kỳ namespace nào (cluster-wide) |

---

## 6. Target (Đối tượng áp dụng)

Policy áp dụng cho workload thông qua hai cách:

### 6.1 Theo tên (Name)
```yaml
target:
  kind: Deployment
  name: nginx-frontend
```
Áp dụng đúng cho 1 Deployment/StatefulSet/DaemonSet/Pod có tên chỉ định.

### 6.2 Theo Label Selector
```yaml
target:
  kind: Deployment
  selector:
    matchLabels:
      app: web
    matchExpressions:
      - key: env
        operator: In
        values: [production, staging]
```
Áp dụng cho tất cả workload khớp label. Các operator: `In`, `NotIn`, `Exists`, `DoesNotExist`.

---

## 7. Hệ thống License

### 7.1 Các trạng thái License

| Trạng thái | Màu | Ý nghĩa |
|---|---|---|
| **trial** | Xanh | Built-in trial 30 ngày từ ngày cài đặt |
| **valid** | Xanh | License đầy đủ, còn hạn |
| **in_grace** | Vàng | Hết hạn nhưng trong grace period |
| **missing** | Đỏ | Chưa có license, hết trial |
| **invalid** | Đỏ | License lỗi (sai chữ ký, sai installation) |

### 7.2 Cơ chế License

- **Thuật toán**: Ed25519 digital signature.
- **Format key**: `VARMOR1.<base64url_payload>.<base64url_signature>`
- **Installation binding**: License có thể bind vào đúng một installation (cluster) cụ thể thông qua `installation_id`.
- **Offline**: Không cần kết nối internet để verify.

### 7.3 Các trường trong License

| Trường | Ý nghĩa |
|---|---|
| `license_id` | Mã định danh license (VD: LIC-VNNIC-001) |
| `customer` | Tên khách hàng |
| `edition` | Phiên bản: `trial`, `starter`, `enterprise` |
| `issued_at` | Ngày phát hành (ISO 8601) |
| `expires_at` | Ngày hết hạn (ISO 8601) |
| `grace_days` | Số ngày gia hạn sau khi hết hạn |
| `features` | Danh sách tính năng: `["*"]` = tất cả |
| `limits.max_nodes` | Số node tối đa (0 = không giới hạn) |
| `limits.max_policies` | Số policy tối đa (0 = không giới hạn) |
| `installation_id` | Binding với installation cụ thể (`vmi_<hash>`) |
| `cluster_uid` | UID của kube-system namespace |

### 7.4 Installation Identity

Mỗi lần cài đặt vArmor tạo ra một **installation identity** duy nhất:

| Trường | Ý nghĩa |
|---|---|
| `installation_uuid` | UUID ngẫu nhiên tạo khi cài |
| `installation_public_key` | Public key Ed25519 của installation |
| `installation_id` | `vmi_` + SHA256 của canonical JSON identity |
| `cluster_uid` | UID của namespace `kube-system` |
| `api_ca_sha256` | SHA256 của CA certificate kube-apiserver |
| `created_at` | Thời điểm cài đặt |

---

## 8. Hệ thống RBAC (Phân quyền)

### 8.1 Built-in Roles

#### admin
Toàn quyền hệ thống. Dành cho người quản trị hệ thống.

#### operator
Quyền tạo và submit policy để admin duyệt. Không thể apply trực tiếp.

#### viewer
Chỉ xem. Không thể tạo, sửa, xóa bất kỳ resource nào.

### 8.2 Danh sách Permissions

| Permission | Mô tả |
|---|---|
| `dashboard:view` | Xem Dashboard |
| `policies:view` | Xem danh sách policy |
| `policies:create` | Tạo policy mới |
| `policies:validate` | Validate policy trước khi apply |
| `policies:submit` | Submit policy để admin duyệt |
| `policies:edit` | Sửa policy đã có |
| `policies:delete` | Xóa policy |
| `policies:apply_direct` | Apply policy trực tiếp (không cần duyệt) |
| `policies:import` | Import policy từ file |
| `policies:export` | Export policy ra file |
| `review:view` | Xem hàng đợi duyệt |
| `review:approve` | Duyệt policy |
| `review:reject` | Từ chối policy |
| `review:cancel` | Hủy yêu cầu đang chờ |
| `logs:view` | Xem security logs |
| `logs:audit` | Xem audit trail |
| `logs:violations` | Xem security violations |
| `logs:apparmor` | Xem AppArmor events |
| `models:view` | Xem behavior models |
| `models:advisor` | Xem gợi ý từ model |
| `models:apply` | Áp dụng model |
| `users:view` | Xem danh sách user |
| `users:create` | Tạo user mới |
| `users:update_role` | Thay đổi role của user |
| `users:reset_password` | Reset mật khẩu user khác |
| `users:delete` | Xóa user |
| `license:view` | Xem thông tin license |
| `license:manage` | Cài đặt/xóa license |

### 8.3 Custom Roles
Admin có thể tạo role tùy chỉnh với bất kỳ tập hợp permission nào từ danh sách trên.

---

## 9. Policy Templates

Hệ thống cung cấp sẵn 72 template chia thành 8 nhóm:

| Nhóm | Số template | Yêu cầu License |
|---|---|---|
| Baseline Hardening | 10 | Không |
| CVE Mitigation | 9 | Không |
| Compliance | 13 | Không |
| Workload Type | 18 | Không |
| Network Egress | 7 | Không |
| Data Protection | 5 | Enterprise |
| Platform Infrastructure | 15 | Enterprise |
| Incident Response | 2 | Enterprise |

---

## 10. API Endpoints chính

| Method | Endpoint | Quyền | Mô tả |
|---|---|---|---|
| GET | `/api/namespaces/:ns/policies` | policies:view | Liệt kê policy theo namespace |
| POST | `/api/policies` | policies:apply_direct | Tạo policy mới |
| PUT | `/api/namespaces/:ns/policies/:name` | policies:edit | Sửa policy |
| DELETE | `/api/namespaces/:ns/policies/:name` | policies:delete | Xóa policy |
| GET | `/api/cluster-policies` | policies:view | Liệt kê cluster policy |
| GET | `/api/license` | license:view | Trạng thái license |
| POST | `/api/license` | license:manage | Cài license |
| DELETE | `/api/license` | license:manage | Xóa license |
| GET | `/api/license/activation-request` | license:view | Lấy activation request |
| GET | `/api/users` | users:view | Danh sách user |
| POST | `/api/users` | users:create | Tạo user |
| DELETE | `/api/users/:username` | users:delete | Xóa user |
| GET | `/api/audit-logs` | logs:audit | Audit trail |
| GET | `/api/apparmor-events` | logs:apparmor | AppArmor events |
| GET | `/api/policy-templates` | policies:view | Danh sách template |
| GET | `/api/policies/backup` | policies:export | Backup policies |
| POST | `/api/policies/restore` | policies:apply_direct | Restore trực tiếp |
| POST | `/api/policies/restore/submit` | policies:submit | Restore qua hàng đợi |

---

## 11. Cấu hình môi trường (Environment Variables)

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `VARMOR_LICENSE_REQUIRED` | false | Bắt buộc phải có license |
| `VARMOR_LICENSE_FAIL_OPEN` | true | Cho phép chạy khi license lỗi |
| `VARMOR_LICENSE_REQUIRE_INSTALLATION_BINDING` | false | Bắt buộc license bind với installation |
| `VARMOR_LICENSE_ALLOW_ENV_PUBLIC_KEY` | false | Cho phép override public key qua env |
| `VARMOR_LICENSE_ALLOW_HS256` | false | Cho phép license dạng HS256 (legacy) |
| `VARMOR_TRIAL_DAYS` | 30 | Số ngày trial built-in (0 = tắt) |
| `VARMOR_LICENSE_FILE` | /app/data/license.json | Đường dẫn file license |

---

## 12. Luồng hoạt động tổng quát

### Tạo và áp Policy (Admin)
```
Admin tạo policy → Validate → Apply trực tiếp
                                   ↓
                          VarmorPolicy CRD tạo trên k8s
                                   ↓
                          vArmor Manager nhận event
                                   ↓
                          vArmor Agent trên node nhận profile
                                   ↓
                          Kernel AppArmor/BPF/Seccomp áp dụng
                                   ↓
                          Policy Status: Ready
```

### Tạo Policy (Operator — qua review)
```
Operator tạo policy → Submit → Hàng đợi chờ duyệt
                                   ↓
                          Admin xem Review Queue
                                   ↓
                          Approve → Apply → Ready
                          Reject  → Hủy bỏ
```

### Quy trình License
```
Cài đặt mới → Built-in Trial 30 ngày tự động
                   ↓ (hết trial)
          Tải Activation Request (có thông tin installation + yêu cầu)
                   ↓
          Gửi cho Vendor
                   ↓
          Vendor ký license bằng private key → VARMOR1.xxx.yyy
                   ↓
          Paste key vào Console → License Valid
```
