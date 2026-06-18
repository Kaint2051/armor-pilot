# vArmor Console — Hướng dẫn sử dụng

## Mục lục
1. [Đăng nhập](#1-đăng-nhập)
2. [Dashboard](#2-dashboard)
3. [Quản lý Policy](#3-quản-lý-policy)
4. [Tạo Policy mới — Hướng dẫn từng bước](#4-tạo-policy-mới--hướng-dẫn-từng-bước)
5. [Xem và chỉnh sửa Policy](#5-xem-và-chỉnh-sửa-policy)
6. [Backup và Restore Policy](#6-backup-và-restore-policy)
7. [Quản lý License](#7-quản-lý-license)
8. [Quản lý Users và Phân quyền](#8-quản-lý-users-và-phân-quyền)
9. [Xem Logs](#9-xem-logs)
10. [Tìm kiếm và lọc Policy](#10-tìm-kiếm-và-lọc-policy)

---

## 1. Đăng nhập

### Truy cập hệ thống
Mở trình duyệt và vào địa chỉ:
```
http://<địa-chỉ-server>:30080
```

### Thông tin đăng nhập mặc định
| Tài khoản | Mật khẩu | Quyền |
|---|---|---|
| `admin` | `Admin@varmor2024` | Toàn quyền |
| `operator1` | `pass1234` | Tạo & submit policy |

### Giải thích màn hình đăng nhập

**Username**: Tên tài khoản (không phân biệt hoa thường).

**Password**: Mật khẩu (phân biệt hoa thường, tối thiểu 6 ký tự).

> Sau khi đăng nhập thành công, hệ thống tự động load Dashboard. Thông tin đăng nhập được lưu trong `localStorage` của trình duyệt — đóng tab không bị logout.

---

## 2. Dashboard

Dashboard hiển thị tổng quan tình trạng hệ thống. Để vào Dashboard, click tab **Dashboard** trên thanh điều hướng.

### Các thẻ thống kê (Stats Cards)

| Thẻ | Ý nghĩa |
|---|---|
| **Total Policies** | Tổng số policy đang tồn tại (namespace + cluster) |
| **NS Policies** | Số VarmorPolicy (namespace-scoped) |
| **Cluster Policies** | Số VarmorClusterPolicy (cluster-wide) |
| **Policies Active** | Số policy đang ở trạng thái Ready (đang bảo vệ) |

### Biểu đồ phân bố

**Policies by Mode**: Phân bố policy theo chế độ bảo mật (EnhanceProtect, RuntimeDefault, v.v.)

**Policies by Enforcer**: Phân bố theo engine thực thi (AppArmor, BPF, Seccomp)

### License Status (góc phải header)
Hiển thị trạng thái license hiện tại. Màu xanh = hợp lệ, màu vàng = sắp hết hạn/grace, màu đỏ = cần chú ý.

---

## 3. Quản lý Policy

Click tab **Policy** trên thanh điều hướng để vào mục quản lý policy.

### Giao diện danh sách Policy

#### Thanh tìm kiếm và lọc
- **Ô Search**: Gõ để tìm theo tên policy, tên target, mode hoặc enforcer.
- **All Scope**: Lọc theo phạm vi — `Namespace` (policy namespace) hoặc `Cluster` (policy toàn cluster).
- **All Mode**: Lọc theo chế độ bảo mật.
- **All Status**: Lọc theo trạng thái — `Ready` (đang chạy), `Pending` (đang xử lý), `Error` (có lỗi).

> Khi đang lọc, dropdown sẽ đổi màu xanh để báo hiệu filter đang active.

#### Bảng danh sách

| Cột | Ý nghĩa |
|---|---|
| ☐ (checkbox) | Chọn nhiều policy để xóa hàng loạt |
| **Name** | Tên policy (màu xanh, dạng monospace) |
| **Scope** | `NS` (namespace) hoặc `Cluster` (toàn cluster) |
| **Target** | Tên workload hoặc `selector` nếu dùng label |
| **Mode** | Chế độ bảo mật đang áp dụng |
| **Enforcer** | Engine thực thi (AppArmor/BPF/Seccomp) |
| **Status** | Trạng thái: `Ready` (xanh), `Pending` (vàng), lỗi (đỏ) |
| **Created** | Ngày tạo policy |
| **Actions** | ✏️ Sửa \| View \| ⬇ Export \| Del |

#### Phân trang
- Mỗi trang hiển thị **10 policy**.
- Dùng nút **← Prev / Next →** hoặc số trang để di chuyển.
- Thông tin trang hiện tại hiển thị dạng: `Trang 1/3 (25 policy)`.

---

## 4. Tạo Policy mới — Hướng dẫn từng bước

Click nút **+ New Policy** để mở wizard tạo policy.

---

### Bước 1: Target (Đối tượng áp dụng)

#### Namespace
**Ý nghĩa**: Namespace Kubernetes nơi workload đang chạy.
**Ví dụ**: `default`, `production`, `monitoring`
> Chỉ có tác dụng khi tạo **Namespace Policy**. Cluster Policy bỏ qua trường này.

#### Scope
| Giá trị | Ý nghĩa |
|---|---|
| **Namespace** | Tạo `VarmorPolicy` — áp dụng trong namespace chỉ định |
| **Cluster** | Tạo `VarmorClusterPolicy` — áp dụng trên toàn cluster |

> Cluster Policy cần quyền `policies:apply_direct` và thường dùng cho system workloads.

#### Target Kind
Loại workload cần bảo vệ:

| Kind | Mô tả |
|---|---|
| **Deployment** | Ứng dụng stateless phổ biến nhất (web server, API) |
| **StatefulSet** | Ứng dụng có state (database, message queue) |
| **DaemonSet** | Chạy trên mọi node (log agent, monitoring) |
| **Pod** | Pod đơn lẻ, không quản lý bởi controller |

#### Target Selection — Theo tên (Name)
**Target Name**: Nhập đúng tên Deployment/StatefulSet/DaemonSet/Pod.

> Dropdown sẽ tự load danh sách workload trong namespace đã chọn.

#### Target Selection — Theo Label Selector
Dùng khi muốn áp policy cho nhiều workload cùng lúc theo label.

**matchLabels**: Key-value pairs phải khớp hoàn toàn.
```
app = nginx
env = production
```

**matchExpressions**: Điều kiện linh hoạt hơn.

| Operator | Ý nghĩa | Ví dụ |
|---|---|---|
| `In` | Giá trị phải thuộc tập hợp | `tier In [frontend, backend]` |
| `NotIn` | Giá trị không được thuộc tập hợp | `env NotIn [dev, test]` |
| `Exists` | Key phải tồn tại (không cần value) | `app Exists` |
| `DoesNotExist` | Key không được tồn tại | `debug DoesNotExist` |

---

### Bước 2: Policy (Chế độ bảo mật)

#### Policy Name
**Ý nghĩa**: Tên định danh duy nhất của policy trong namespace/cluster.
**Quy tắc**: Chỉ dùng chữ thường, số, dấu gạch ngang (`-`). Không dùng dấu chấm, gạch dưới hay khoảng trắng.
**Ví dụ**: `protect-nginx`, `harden-payment-api`, `secure-database`

> Sau khi tạo, **không thể đổi tên** policy. Muốn đổi tên phải xóa và tạo lại.

#### Mode (Chế độ bảo mật)

Chọn một trong 5 chế độ:

| Mode | Mức độ bảo vệ | Dùng khi |
|---|---|---|
| **AlwaysAllow** | Không bảo vệ | Debug, testing |
| **RuntimeDefault** | Thấp - baseline | Workload thông thường |
| **EnhanceProtect** | Trung-Cao | Production, cần bảo vệ nâng cao |
| **BehaviorModeling** | Chỉ quan sát | Giai đoạn học hành vi |
| **DefenseInDepth** | Cao nhất | Sau khi đã có model |

#### Enforcer (Engine thực thi)

Chọn một hoặc nhiều engine. Có thể chọn kết hợp:

| Engine | Bảo vệ | Yêu cầu |
|---|---|---|
| **AppArmor** | File, capabilities, network | AppArmor kernel module |
| **BPF** | Syscall, file, network, process | Kernel ≥ 5.10, BTF |
| **Seccomp** | Syscall filtering | Kernel ≥ 3.17 |
| **NetworkProxy** | Egress network control | BPF available |

> Nếu node không hỗ trợ engine đã chọn, policy sẽ ở trạng thái **Error**.

---

### Bước 3: Rules (Luật bảo mật)

Chỉ áp dụng khi chọn mode **EnhanceProtect**.

#### 3.1 Hardening Rules (Khóa điểm yếu hệ thống)

Chọn từ danh sách các rule có sẵn. Mỗi rule khóa một vector tấn công cụ thể.

| Rule | Bảo vệ khỏi |
|---|---|
| `disable-cap-all` | Tước toàn bộ Linux capabilities (mạnh nhất) |
| `disable-cap-privileged` | Tước các capability nguy hiểm (CAP_SYS_ADMIN, v.v.) |
| `disable-cap-all-except-net-bind-service` | Chỉ giữ lại quyền bind port |
| `disallow-mount` | Chặn mount filesystem |
| `disallow-insmod` | Chặn load kernel module |
| `disallow-load-bpf-prog` | Chặn load eBPF program |
| `disallow-write-core-pattern` | Ngăn ghi /proc/sys/kernel/core_pattern |
| `disallow-mount-procfs` | Ngăn mount /proc |
| `disallow-create-user-ns` | Ngăn tạo user namespace (chặn container escape) |
| `disallow-abuse-user-ns` | Ngăn lạm dụng user namespace |
| `disallow-access-procfs-root` | Ngăn truy cập /proc/[pid]/root |
| `disallow-access-kallsyms` | Ngăn đọc /proc/kallsyms (lộ kernel address) |
| `disallow-debug-disk-device` | Ngăn truy cập raw disk device |

#### 3.2 Attack Protection Rules (Chặn kỹ thuật tấn công)

Chặn các kỹ thuật tấn công sau khi attacker đã vào được container.

**Chặn công cụ nguy hiểm trong container**:
| Rule | Tác dụng |
|---|---|
| `disable-shell` | Chặn bash, sh, zsh, dash (không RCE qua shell) |
| `disable-wget` | Chặn wget (không download payload) |
| `disable-curl` | Chặn curl |
| `disable-chmod` | Chặn chmod (không thay đổi quyền file) |
| `disable-su-sudo` | Chặn su/sudo (không leo thang quyền) |
| `disable-busybox` | Chặn busybox (Swiss Army knife của attacker) |

**Chặn truy cập thông tin nhạy cảm**:
| Rule | Tác dụng |
|---|---|
| `disable-write-etc` | Ngăn ghi vào /etc (không sửa hosts, passwd) |
| `disable-access-passwd` | Ngăn đọc /etc/passwd |
| `disable-access-shadow` | Ngăn đọc /etc/shadow (mật khẩu hash) |
| `disable-access-ssh-dir` | Ngăn đọc ~/.ssh (private key) |
| `mitigate-sa-leak` | Ngăn đọc ServiceAccount token (k8s credential) |
| `mitigate-host-ip-leak` | Ngăn lộ IP của host node |

**Chặn truy cập metadata cloud**:
| Rule | Cloud Provider |
|---|---|
| `block-access-to-metadata-service` | Generic (169.254.169.254) |
| `block-access-to-aws-metadata-service` | AWS EC2 |
| `block-access-to-alibaba-metadata-service` | Alibaba Cloud |
| `block-access-to-oci-metadata-service` | Oracle Cloud |

**Kiểm soát network**:
| Rule | Tác dụng |
|---|---|
| `disable-network` | Chặn toàn bộ network |
| `disable-inet` | Chặn IPv4 và IPv6 |
| `disable-ipv4` / `disable-inet` | Chặn IPv4 |
| `disable-ipv6` / `disable-inet6` | Chặn IPv6 |
| `disable-tcp` | Chặn TCP |
| `disable-udp` | Chặn UDP |
| `disable-icmp` | Chặn ICMP (ping) |
| `block-access-to-kube-apiserver` | Chặn truy cập k8s API server |
| `block-access-to-container-runtime` | Chặn socket container runtime (Docker escape) |

#### 3.3 Vulnerability Mitigation Rules (Vá CVE)

| Rule | CVE | Mô tả |
|---|---|---|
| `dirty-pipe-mitigation` | CVE-2022-0847 | Dirty Pipe — ghi vào file read-only |
| `runc-override-mitigation` | CVE-2019-5736 | runc override — escape container |
| `cgroups-lxcfs-escape-mitigation` | - | Thoát container qua cgroups/lxcfs |
| `ingress-nightmare-mitigation` | CVE-2025-1974 | IngressNightmare — RCE qua ingress |
| `copy-fail-mitigation` | - | Lỗi liên quan đến copy trong container |

#### 3.4 AppArmor Raw Rules
Nhập trực tiếp các rule AppArmor profile nếu cần kiểm soát chi tiết hơn.
```
/etc/nginx/nginx.conf r,
/var/log/nginx/ rw,
```

#### 3.5 BPF Raw Rules
Cấu hình eBPF rules trực tiếp khi cần kiểm soát đặc biệt.

#### 3.6 Seccomp Rules
Chỉ định danh sách syscall được phép hoặc bị chặn.

**Syscall Actions**:
| Action | Ý nghĩa |
|---|---|
| `SCMP_ACT_KILL` | Kill process ngay lập tức khi gọi syscall này |
| `SCMP_ACT_ERRNO` | Trả về lỗi (EPERM) — process tiếp tục chạy |
| `SCMP_ACT_LOG` | Ghi log nhưng cho phép |
| `SCMP_ACT_ALLOW` | Cho phép hoàn toàn |

---

### Bước 4: Review (Xem lại trước khi apply)

Xem lại toàn bộ cấu hình trước khi tạo policy.

#### Nút Validate
Kiểm tra cú pháp và tính hợp lệ của policy. Phải validate thành công trước khi có thể apply.

**Kết quả Validate**:
- ✅ **Valid**: Policy hợp lệ, có thể apply.
- ❌ **Invalid**: Có lỗi cú pháp, xem thông báo lỗi bên dưới.

#### Nút Apply (Chỉ Admin)
Apply policy trực tiếp vào cluster. Policy sẽ xuất hiện trong danh sách ngay.

#### Nút Submit for Review (Operator)
Gửi policy vào hàng đợi chờ Admin duyệt. Admin sẽ thấy trong tab Review.

---

## 5. Xem và chỉnh sửa Policy

### Xem chi tiết policy
Click nút **View** trong cột Actions để xem chi tiết đầy đủ CRD YAML của policy.

### Sửa policy
Click nút **✏️ (Edit)** để mở lại wizard với thông tin đã điền sẵn.

> Không thể thay đổi: **tên policy**, **scope** (namespace/cluster), **namespace**.

### Export policy
Click nút **⬇** để tải về file YAML của policy.

### Xóa policy
Click nút **Del** → confirm dialog → policy bị xóa khỏi cluster.

> Xóa policy sẽ **dừng bảo vệ ngay lập tức** cho workload đó.

### Xóa hàng loạt
Tick checkbox nhiều policy → Nút **Delete Selected** xuất hiện → Confirm xóa tất cả đã chọn.

---

## 6. Backup và Restore Policy

### Backup
Click nút **⬇ Backup** trên thanh toolbar.

**Tùy chọn**:
- ☑ **Namespace policies**: Backup VarmorPolicy trong namespace hiện tại.
- ☑ **Cluster policies**: Backup VarmorClusterPolicy.

File backup là JSON array chứa spec của tất cả policy (không có runtime fields như status, uid, resourceVersion).

### Restore

Click nút **↺ Restore** để mở panel restore.

**Bước 1**: Chọn file backup JSON đã tải trước đó.

**Bước 2**: Chọn chế độ xử lý khi policy đã tồn tại:

| Chế độ | Hành vi |
|---|---|
| **Skip existing** | Bỏ qua policy đã có, chỉ tạo mới những cái chưa có |
| **Overwrite existing** | Ghi đè lên policy đã có bằng version từ backup |

**Bước 3**:
- **Restore Directly** (Admin): Apply ngay không cần duyệt.
- **Submit for Review** (Operator): Gửi vào hàng đợi.

---

## 7. Quản lý License

Click tab **Users/Access Control** → chọn **License** trong sub-menu bên trái.

### 7.1 Xem trạng thái License

**License Status Card** hiển thị:

| Trường | Ý nghĩa |
|---|---|
| **Status** | trial / valid / in_grace / missing / invalid |
| **Edition** | trial / starter / enterprise |
| **Customer** | Tên khách hàng trong license |
| **License ID** | Mã license (VD: LIC-VNNIC-001) |
| **Issued At** | Ngày phát hành |
| **Expires At** | Ngày hết hạn |
| **Days Remaining** | Số ngày còn lại |
| **Grace Days** | Số ngày gia hạn sau hết hạn |
| **Installation ID** | Mã nhận dạng installation (`vmi_...`) |
| **Cluster UID** | UID của kube-system namespace |
| **Max Nodes** | Giới hạn số node (0 = không giới hạn) |
| **Max Policies** | Giới hạn số policy (0 = không giới hạn) |
| **Features** | `["*"]` = tất cả tính năng |

### 7.2 Tải Activation Request (Yêu cầu cấp License)

Khi cần xin license từ vendor:

1. Click nút **Download Activation Request**.
2. Điền thông tin liên hệ:

| Trường | Bắt buộc | Ý nghĩa |
|---|---|---|
| **Họ và tên** | ✅ | Người liên hệ |
| **Công ty / Tổ chức** | ✅ | Tên đơn vị sử dụng |
| **Email liên hệ** | ✅ | Email nhận license |
| **Số điện thoại** | ❌ | Số điện thoại liên hệ |

3. Điền thông tin yêu cầu license:

| Trường | Ý nghĩa |
|---|---|
| **Edition** | `Enterprise` (đầy đủ) / `Starter` / `Trial` |
| **Thời hạn** | 1 năm / 2 năm / 3 tháng / 30 ngày / Khác |
| **Max nodes** | Số node tối đa cần dùng (0 = không giới hạn) |
| **Max policies** | Số policy tối đa cần dùng (0 = không giới hạn) |
| **Ghi chú** | Mô tả thêm về môi trường, mục đích sử dụng |

4. Click **Tải xuống** — file `varmor-activation-request.json` được tải về.
5. Gửi file này cho vendor.

### 7.3 Nhập License Key

Sau khi nhận license từ vendor (dạng `VARMOR1.xxx.yyy`):

1. Paste chuỗi license vào ô **License Key**.
2. Click **Save License**.
3. Hệ thống verify và cập nhật trạng thái ngay lập tức.

**Lỗi thường gặp**:

| Lỗi | Nguyên nhân |
|---|---|
| `invalid signature` | License bị sửa hoặc ký sai key |
| `installation_id mismatch` | License bind cho máy khác |
| `license has expired` | License đã hết hạn và qua grace period |
| `license key string is required` | Ô nhập trống |

### 7.4 Xóa License

Click **Remove License** (màu đỏ) → confirm → license bị xóa. Hệ thống quay về trạng thái chưa activate (nếu hết trial sẽ vào trạng thái locked).

### 7.5 Tạo License (Dành cho Vendor)

Vendor dùng CLI tool trên máy có private key:

```powershell
cd varmor-console

python tools/license_tool.py sign `
  --private-key license-test/test-license-private.pem `
  --activation-request path\to\varmor-activation-request.json `
  --license-id LIC-CUSTOMER-001 `
  --customer "Ten khach hang" `
  --edition enterprise `
  --days 365 `
  --output customer-license.key
```

**Tham số đầy đủ**:

| Tham số | Bắt buộc | Ý nghĩa |
|---|---|---|
| `--private-key` | ✅ | Đường dẫn file PEM vendor private key |
| `--activation-request` | ✅ | File JSON activation request của khách |
| `--license-id` | ✅ | Mã license (VD: LIC-VNNIC-001) |
| `--customer` | ✅ | Tên khách hàng |
| `--edition` | ❌ | trial / starter / enterprise (mặc định: enterprise) |
| `--days` | ❌ | Số ngày hợp lệ (mặc định: 365) |
| `--grace-days` | ❌ | Số ngày gia hạn sau hết hạn (mặc định: 14) |
| `--max-nodes` | ❌ | Giới hạn node (0 = không giới hạn) |
| `--max-policies` | ❌ | Giới hạn policy (0 = không giới hạn) |
| `--features` | ❌ | Tính năng: `*` hoặc `f1,f2,...` |
| `--output` | ❌ | File output (mặc định: in ra màn hình) |

---

## 8. Quản lý Users và Phân quyền

Click tab **Users/Access Control** → chọn **Users** trong sub-menu.

> Chỉ tài khoản **admin** mới thấy mục này.

### 8.1 Danh sách Users

Bảng hiển thị tất cả tài khoản trong hệ thống:

| Cột | Ý nghĩa |
|---|---|
| **Username** | Tên đăng nhập |
| **Role** | Vai trò: `admin` / `operator` / `viewer` hoặc custom role |
| **Created** | Ngày tạo tài khoản |
| **Actions** | Đổi mật khẩu \| Đổi role \| Xóa |

### 8.2 Tạo User mới

Click **+ New User**.

| Trường | Ý nghĩa |
|---|---|
| **Username** | Tên đăng nhập, duy nhất trong hệ thống |
| **Password** | Mật khẩu (tối thiểu 6 ký tự) |
| **Role** | Vai trò ban đầu của user |

### 8.3 Các Roles (Vai trò)

| Role | Mô tả tóm tắt |
|---|---|
| **admin** | Toàn quyền — tạo/sửa/xóa/apply policy, quản lý user, quản lý license |
| **operator** | Tạo và submit policy để admin duyệt; xem logs, models |
| **viewer** | Chỉ xem — không thể tạo, sửa, xóa bất kỳ thứ gì |

### 8.4 Custom Roles

Click **Roles** trong sub-menu để xem và quản lý custom roles.

Có thể tạo role với bất kỳ tập hợp permission nào từ 26 permission có sẵn. Ví dụ: tạo role `log-analyst` chỉ có `logs:view` + `logs:violations` + `logs:apparmor`.

### 8.5 Đổi mật khẩu

- **Tự đổi mật khẩu của mình**: Vào profile → Change Password.
- **Admin đổi mật khẩu người khác**: Click icon chìa khóa cạnh tên user.

---

## 9. Xem Logs

Click tab **Logs** trên thanh điều hướng.

### 9.1 Security Events (Vi phạm bảo mật)

Hiển thị các sự kiện bị chặn bởi policy (AppArmor denials, BPF blocks).

| Cột | Ý nghĩa |
|---|---|
| **Time** | Thời gian xảy ra sự kiện |
| **Namespace** | Namespace của pod |
| **Pod** | Tên pod phát sinh sự kiện |
| **Profile** | AppArmor profile đang áp dụng |
| **Operation** | Hành động bị chặn (exec, open, connect, v.v.) |
| **Denied** | Resource bị chặn (file path, network address) |
| **Severity** | Mức độ nghiêm trọng |

Click vào một sự kiện để xem chi tiết và gợi ý xử lý.

### 9.2 Audit Trail (Lịch sử hành động)

Ghi lại mọi hành động trong console (ai làm gì, lúc nào, kết quả ra sao).

| Cột | Ý nghĩa |
|---|---|
| **Time** | Thời gian thực hiện |
| **User** | Tài khoản thực hiện |
| **Action** | Hành động: CREATE_POLICY, DELETE_USER, UPDATE_LICENSE, v.v. |
| **Resource** | Loại tài nguyên bị tác động |
| **Target** | Tên cụ thể của tài nguyên |
| **Result** | SUCCESS / FAILURE |
| **Detail** | Thông tin chi tiết |

### 9.3 AppArmor Profiles

Hiển thị trạng thái các AppArmor profile đang được load trên các node.

| Trạng thái | Ý nghĩa |
|---|---|
| **loaded** | Profile đang active trên node |
| **unloaded** | Profile chưa/không được load |

---

## 10. Tìm kiếm và lọc Policy

### Search (Tìm theo từ khóa)
Gõ vào ô search để tìm theo:
- Tên policy
- Tên target workload
- Tên mode
- Tên enforcer
- Scope

### Filter Scope
| Giá trị | Hiện |
|---|---|
| All Scope | Tất cả |
| Namespace | Chỉ VarmorPolicy (namespace-scoped) |
| Cluster | Chỉ VarmorClusterPolicy |

### Filter Mode
Chọn một mode cụ thể để chỉ hiện policy của mode đó.

### Filter Status
| Giá trị | Hiện |
|---|---|
| All Status | Tất cả |
| Ready | Chỉ policy đang hoạt động bình thường |
| Pending | Policy đang xử lý (vừa tạo hoặc đang cập nhật) |
| Error | Policy bị lỗi (node không hỗ trợ enforcer, spec sai, v.v.) |

> Các filter kết hợp với nhau và với search đồng thời.
> Khi filter active, dropdown đổi màu xanh để dễ nhận biết.

---

## Phụ lục: Giải thích trạng thái Policy

| Status | Phase | Ý nghĩa | Cần làm |
|---|---|---|---|
| Ready | Protecting | Policy đang bảo vệ workload | Không |
| Pending | Pending | Đang tạo/cập nhật | Chờ |
| Pending | Modeling | BehaviorModeling đang chạy | Chờ đủ thời gian |
| Pending | Completed | Modeling xong, chờ apply | Apply DefenseInDepth |
| Error | Error | Lỗi không thể áp dụng | Xem detail → sửa |
| Error | Failed | Thất bại khi load profile | Kiểm tra node logs |

## Phụ lục: Phím tắt và mẹo

- **Ctrl+Shift+R**: Reload trang, xóa browser cache — dùng khi không thấy thay đổi mới nhất.
- **Refresh button** (↺) trên bảng policy: Reload danh sách từ k8s mà không reload toàn trang.
- **Select All**: Tick checkbox ở header để chọn tất cả policy đang hiển thị trong trang.
- **Export YAML**: Click ⬇ để tải YAML của một policy, dùng để backup hoặc apply thủ công qua `kubectl`.
