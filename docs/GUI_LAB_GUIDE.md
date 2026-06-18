# Hướng Dẫn Tự Lab: ArmorPilot — Giao Diện + Dòng Lệnh
## Học Bảo Mật Container Qua Giao Diện Đồ Hoạ và Xác Minh Bằng CLI

> **Truy cập Console:** mở trình duyệt → `http://172.30.2.129:8080`  
> **Tài khoản:** `admin` / `Admin@ArmorPilot2026!`
> **SSH vào server:** `ssh root@172.30.2.129` (password: `abc@123`)  
> **Triết lý hướng dẫn:** Làm trên GUI → Kiểm chứng bằng `kubectl` → Hiểu tại sao

---

## Mục Lục

- [Phần A — Làm Quen Với Giao Diện](#phần-a--làm-quen-với-giao-diện)
- [Lab 01 — Đăng Nhập & Bảo Mật](#lab-01--đăng-nhập--bảo-mật)
- [Lab 02 — Đọc Danh Sách Deployment](#lab-02--đọc-danh-sách-deployment)
- [Lab 03 — Tạo Policy Đầu Tiên](#lab-03--tạo-policy-đầu-tiên)
- [Lab 04 — Chặn File Nhạy Cảm Qua GUI](#lab-04--chặn-file-nhạy-cảm-qua-gui)
- [Lab 05 — Bảo Vệ Container Escape](#lab-05--bảo-vệ-container-escape)
- [Lab 06 — Quan Sát Audit Log Real-time](#lab-06--quan-sát-audit-log-real-time)
- [Lab 07 — Xác Minh RBAC & Phân Quyền](#lab-07--xác-minh-rbac--phân-quyền)

---

## Phần A — Làm Quen Với Giao Diện

### A.1 Mở Console trong trình duyệt

Mở trình duyệt và vào địa chỉ: **`http://172.30.2.129:8080`**

Bạn sẽ thấy **trang đăng nhập**:

```
┌─────────────────────────────────────────────┐
│                                             │
│          ┌──────────────────────┐           │
│          │   [🛡]               │           │
│          │   ArmorPilot     │           │
│          │   Kubernetes Security│           │
│          │   Policy Manager     │           │
│          │                      │           │
│          │  Username            │           │
│          │  ┌──────────────────┐│           │
│          │  │ admin            ││           │
│          │  └──────────────────┘│           │
│          │                      │           │
│          │  Password            │           │
│          │  ┌──────────────────┐│           │
│          │  │ ••••••••••••••••• ││           │
│          │  └──────────────────┘│           │
│          │                      │           │
│          │  ┌──────────────────┐│           │
│          │  │    Sign In       ││           │
│          │  └──────────────────┘│           │
│          └──────────────────────┘           │
└─────────────────────────────────────────────┘
```

**Tại sao có trang đăng nhập?**  
Console giao tiếp với Kubernetes API — nếu không có auth, bất kỳ ai truy cập URL đều có thể tạo/xóa policy bảo mật. Đây là **bảo vệ lớp đầu tiên**.

### A.2 Bố cục Dashboard sau khi đăng nhập

```
┌────────────────────────────────────────────────────────────────────────┐
│ [🛡] ArmorPilot    Namespace: [default] [Load]    👤 admin [Logout]│
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌──────────────────────────────────────┐  ┌─────────────────────────┐│
│  │ ➕ Create VarmorPolicy               │  │ 🖥 Deployments          ││
│  │                                      │  │                         ││
│  │  Policy Name *  Target Deployment *  │  │ ┌─────────────────────┐ ││
│  │  [__________]   [▼ select deploy ]   │  │ │ armor-pilot      │ ││
│  │                                      │  │ │ 1/1 replicas        │ ││
│  │  Kernel Enforcers:                   │  │ │     🛡 Protected     │ ││
│  │  [✓] AppArmor [ ] Seccomp            │  │ └─────────────────────┘ ││
│  │  [ ] BPF      [ ] NetworkProxy       │  │                         ││
│  │                                      │  │ ┌─────────────────────┐ ││
│  │  Built-in Defense Rules:             │  │ │ nginx-deploy        │ ││
│  │  [ ] Container Escape Prevention     │  │ │ 2/2 replicas        │ ││
│  │  [ ] Privilege Escalation Prevention │  │ │     ⚠ No Shield     │ ││
│  │                                      │  │ └─────────────────────┘ ││
│  │  Banned File Paths (one per line):   │  └─────────────────────────┘│
│  │  ┌───────────────────────────────┐   │                             │
│  │  │                               │   │                             │
│  │  │                               │   │                             │
│  │  └───────────────────────────────┘   │                             │
│  │                                      │                             │
│  │                   [ Apply Policy ]   │                             │
│  └──────────────────────────────────────┘                             │
│                                                                        │
│  ┌────────────────────────────────────────────────────────────────────┐│
│  │ ≡ Active Policies                                       [⟳ Refresh]││
│  ├──────────────┬──────────┬─────────────┬────────┬────────┬─────────┤│
│  │ Name         │ Target   │ Enforcer    │ Status │Created │ Actions ││
│  ├──────────────┼──────────┼─────────────┼────────┼────────┼─────────┤│
│  │ my-policy    │ nginx    │ EnhanceProt │ Ready  │2026-05 │[Delete] ││
│  └──────────────┴──────────┴─────────────┴────────┴────────┴─────────┘│
└────────────────────────────────────────────────────────────────────────┘
```

**Giải thích từng khu vực:**

| Khu vực | Chức năng | Tại sao thiết kế vậy |
|---|---|---|
| Header — Namespace | Lọc dữ liệu theo namespace K8s | K8s phân chia workload theo namespace; "default" là namespace thử nghiệm |
| Header — Load | Reload deployment + policy list | Dữ liệu không tự refresh để tránh overload API |
| Sidebar phải — Deployments | Danh sách deployment + trạng thái bảo vệ | Chọn nhanh target khi tạo policy |
| Form trái — Create Policy | Tạo VarmorPolicy mới | Form validate trước khi gửi lên K8s |
| Bảng dưới — Active Policies | Danh sách policy đang chạy | Quản lý vòng đời policy |

### A.3 Badge trạng thái

```
🛡 Protected   ← xanh lá  → deployment có label sandbox.varmor.org/enable=true
⚠  No Shield   ← vàng     → deployment CHƯA có policy bảo vệ
──────────────────────────────────────────────
● Ready        ← xanh lá  → policy đã được vArmor xử lý
○ Pending      ← vàng     → policy vừa tạo, đang chờ xử lý
```

---

## Lab 01 — Đăng Nhập & Bảo Mật

### Mục tiêu
Hiểu cơ chế đăng nhập, thử các trường hợp lỗi, và kiểm tra bảo mật API.

### Bước 1.1 — Đăng nhập sai để xem phản ứng

Trong trang đăng nhập, thử:
- **Username:** `admin`  
- **Password:** `saimatkhau`

Nhấn **Sign In**.

```
┌──────────────────────────────────┐
│  ┌────────────────────────────┐  │
│  │ ⛔ Invalid username or     │  │
│  │    password.               │  │
│  └────────────────────────────┘  │
└──────────────────────────────────┘
```

**Quan sát:** Thông báo lỗi nói "Invalid username or password" — không nói rõ sai username hay sai password.

**Tại sao?** Nếu server phân biệt "username không tồn tại" vs "password sai", attacker biết được username nào hợp lệ → **user enumeration attack**. Thông báo mơ hồ bảo vệ chống điều này.

### Bước 1.2 — Đăng nhập đúng

- **Username:** `admin`  
- **Password:** `Admin@ArmorPilot2026!`

Nhấn **Sign In** → Dashboard xuất hiện.

**Điều gì xảy ra bên trong (mở DevTools F12 > Network để xem):**

```
Browser                          Server
  │                                │
  ├─ POST  /api/namespaces/...  ──►│   (test credentials)
  │   Authorization: Basic YWRtaW4...
  │                                ├─ decode base64 → admin:Admin@ArmorPilot2026!
  │                                ├─ so sánh với env ADMIN_USER/ADMIN_PASS
  │◄─ 200 OK ─────────────────────┤
  │                                │
  │ → lưu vào localStorage         │
  │ → hiển thị Dashboard           │
```

### Bước 1.3 — Kiểm tra session được lưu trong browser

Mở **DevTools (F12) → Application → Local Storage → http://172.30.2.129:8080**

Bạn sẽ thấy key `va_auth` với value dạng JSON:
```json
{"header":"Basic YWRtaW46QWRtaW5AdkFybW9yMjAyNiE=","user":"admin"}
```

**Tại sao lưu trong localStorage?** Để không phải đăng nhập lại khi reload trang. Khi mở tab mới, browser đọc token từ localStorage và tự đăng nhập.

**Rủi ro bảo mật của localStorage?** JavaScript trên trang có thể đọc — nếu có XSS vulnerability, attacker có thể đánh cắp token. Trong production nên dùng HttpOnly cookie thay thế.

### Bước 1.4 — Xác minh API bảo vệ đúng (từ SSH terminal)

```bash
# Trên server terminal:

# Thử không có auth
curl -s http://127.0.0.1:8080/api/namespaces/default/policies
# → {"error": "Authentication required"}

# Xem HTTP status code
curl -o /dev/null -w "HTTP Status: %{http_code}\n" \
     http://127.0.0.1:8080/api/namespaces/default/policies
# → HTTP Status: 401

# Trang HTML chính KHÔNG cần auth
curl -o /dev/null -w "HTTP Status: %{http_code}\n" \
     http://127.0.0.1:8080/
# → HTTP Status: 200
```

**Tại sao trang HTML không cần auth?** HTML chỉ là "vỏ" tĩnh — không chứa dữ liệu nhạy cảm. Dữ liệu thật được fetch qua `/api/*` sau khi đã đăng nhập.

### Bước 1.5 — Logout và thử lại

Nhấn **Logout** ở góc trên phải → quay về trang đăng nhập.

Kiểm tra localStorage đã bị xóa: **DevTools → Application → Local Storage** → key `va_auth` không còn.

---

## Lab 02 — Đọc Danh Sách Deployment

### Mục tiêu
Hiểu sidebar Deployments, ý nghĩa badge, và cách namespace ảnh hưởng đến dữ liệu hiển thị.

### Bước 2.1 — Đọc Deployment sidebar

Sau khi đăng nhập, nhìn vào **sidebar bên phải** (Deployments panel):

```
┌─────────────────────────────────┐
│ 🖥 Deployments          [⟳]     │
│                                  │
│ ┌──────────────────────────────┐ │
│ │ armor-pilot               │ │
│ │ 1/1 replicas   🛡 Protected  │ │
│ └──────────────────────────────┘ │
│                                  │
│ ┌──────────────────────────────┐ │
│ │ (các deployment khác...)     │ │
│ │                ⚠ No Shield   │ │
│ └──────────────────────────────┘ │
└─────────────────────────────────┘
```

`1/1 replicas` = "1 pod đang chạy / 1 pod yêu cầu" → deployment healthy.

### Bước 2.2 — Tạo deployment mới để thử nghiệm (SSH)

```bash
# Trên server:
kubectl create deployment lab02-nginx --image=nginx:alpine
```

### Bước 2.3 — Refresh Deployments trên GUI

Nhấn nút **⟳** (icon tròn) cạnh chữ "Deployments" trong sidebar.

Bạn sẽ thấy `lab02-nginx` xuất hiện với badge **⚠ No Shield** vì chưa có policy.

**Tại sao phải nhấn Refresh?** Dashboard không tự động poll K8s (để tránh request liên tục). Bạn chủ động refresh khi cần dữ liệu mới — đây là "pull model" thay vì "push model".

### Bước 2.4 — Thêm label vArmor và xem badge thay đổi

```bash
# Trên server:
kubectl label deployment lab02-nginx sandbox.varmor.org/enable=true
```

Quay lại browser → nhấn **⟳** refresh sidebar.

Badge `lab02-nginx` đổi thành **🛡 Protected**.

**Nhưng chờ đã** — Protected badge chỉ nói deployment *có label* vArmor, không chắc có policy thật không. Kiểm tra bảng "Active Policies" — `lab02-nginx` chưa có policy nào trong đó.

**Điều này dạy gì?** Badge Protected = **deployment được đánh dấu để bảo vệ**, không phải đã có profile AppArmor thật. Policy phải được tạo riêng.

### Bước 2.5 — Thử namespace khác

Trong header, đổi ô **Namespace** từ `default` → `kube-system`, nhấn **Load**.

Sidebar Deployments sẽ hiện các deployment của K8s core (coredns...).

**Tại sao cần namespace filter?** Kubernetes phân chia workload theo namespace — bạn không muốn nhìn thấy tất cả khi chỉ cần quản lý một phần.

### Bước 2.6 — Dọn dẹp

Đổi namespace về `default`, nhấn Load.

```bash
# Trên server:
kubectl delete deployment lab02-nginx
```

Nhấn **⟳** refresh → `lab02-nginx` biến mất.

---

## Lab 03 — Tạo Policy Đầu Tiên

### Mục tiêu
Tạo VarmorPolicy qua GUI, hiểu từng trường trong form, và xác minh K8s CRD được tạo.

### Bước 3.1 — Chuẩn bị deployment target

```bash
# Trên server:
kubectl create deployment lab03-webapp --image=nginx:alpine
```

Nhấn **⟳** refresh sidebar → thấy `lab03-webapp` với badge ⚠ No Shield.

### Bước 3.2 — Điền form Create Policy

Nhìn vào form **Create VarmorPolicy** bên trái:

```
┌──────────────────────────────────────────────────────┐
│ ➕ Create VarmorPolicy                               │
│                                                      │
│  Policy Name *          Target Deployment *          │
│  ┌────────────────┐    ┌────────────────────────┐    │
│  │ protect-webapp │    │ ▼ lab03-webapp         │    │
│  └────────────────┘    └────────────────────────┘    │
│                                                      │
│  Kernel Enforcers:                                   │
│  [✓] AppArmor  [ ] Seccomp  [ ] BPF  [ ] NetProxy   │
│                                                      │
│  Built-in Defense Rules:                             │
│  [ ] Container Escape Prevention                     │
│  [ ] Privilege Escalation Prevention                 │
│                                                      │
│  Banned File Paths (one per line):                   │
│  ┌──────────────────────────────────────────────┐   │
│  │ (để trống lần này)                           │   │
│  └──────────────────────────────────────────────┘   │
│                                                      │
│                          [ Apply Policy ]            │
└──────────────────────────────────────────────────────┘
```

**Điền:**
- **Policy Name:** `protect-webapp`
- **Target Deployment:** chọn `lab03-webapp` từ dropdown
- **Enforcers:** chỉ giữ `AppArmor` ✓ (mặc định)
- **Rules:** để trống tất cả
- **Banned Files:** để trống

Nhấn **Apply Policy**.

### Bước 3.3 — Đọc phản hồi thành công

```
┌──────────────────────────────────────────────────┐
│  ✓ Policy "protect-webapp" applied successfully. │
└──────────────────────────────────────────────────┘
```

Sau ~1.2 giây, bảng **Active Policies** tự refresh và `protect-webapp` xuất hiện.

### Bước 3.4 — Đọc bảng Active Policies

```
┌────────────────┬──────────────┬─────────────┬─────────┬────────┬─────────┐
│ Name           │ Target       │ Enforcer    │ Status  │Created │ Actions │
├────────────────┼──────────────┼─────────────┼─────────┼────────┼─────────┤
│ protect-webapp │ lab03-webapp │ EnhanceProt │ Pending │2026-05 │[Delete] │
└────────────────┴──────────────┴─────────────┴─────────┴────────┴─────────┘
```

**Giải thích cột:**
- **Status = Pending**: vArmor manager chưa xử lý xong (varmor-agent cần load AppArmor profile)
- **Enforcer = EnhanceProt**: rút gọn từ "EnhanceProtect" — mode policy

**Nhấn ⟳ Refresh** sau vài giây → Status có thể đổi sang "Ready" (nếu agent đang chạy).

### Bước 3.5 — Xác minh CRD thật trong Kubernetes (SSH)

```bash
# Trên server — xác minh policy thật sự tồn tại trong K8s:
kubectl get varmorpolicies -n default

# Xem chi tiết
kubectl get varmorpolicy protect-webapp -n default -o yaml
```

**Output key cần chú ý:**
```yaml
spec:
  target:
    kind: Deployment
    name: lab03-webapp       # ← tên deployment bạn chọn
  policy:
    enforcer: AppArmor       # ← enforcer bạn tick
    mode: EnhanceProtect     # ← GUI tự set mode này
    enhanceProtect:
      attackProtectionRules: []  # ← vì bạn không chọn rules nào
```

**Điều này chứng minh:** GUI tạo CRD thật trong Kubernetes — không phải chỉ lưu trong database riêng. K8s là source of truth.

### Bước 3.6 — Thử validation: điền thiếu field

Xóa tên policy (để trống), nhấn **Apply Policy**.

```
┌──────────────────────────────────┐
│  ⛔ Policy name is required.    │
└──────────────────────────────────┘
```

Thử không chọn Target Deployment:

```
┌──────────────────────────────────────────────┐
│  ⛔ Please select a target deployment.       │
└──────────────────────────────────────────────┘
```

**Tại sao validate ở frontend?** Tránh round-trip đến server cho lỗi đơn giản → UX tốt hơn. Nhưng server **cũng** validate lại — không tin tưởng client 100%.

### Bước 3.7 — Xóa policy qua GUI

Nhấn nút **Delete** ở cuối hàng `protect-webapp` → modal xác nhận xuất hiện:

```
┌──────────────────────────────────────────────┐
│  Confirm Deletion                            │
│                                              │
│  You are about to permanently delete:        │
│  protect-webapp                              │
│                                              │
│            [Cancel]    [Delete Policy]       │
└──────────────────────────────────────────────┘
```

**Tại sao cần confirm modal?** Xóa policy là **action không thể hoàn tác** — nếu xóa nhầm, container bị mất bảo vệ ngay lập tức. Modal buộc bạn đọc tên policy trước khi xác nhận.

Nhấn **Delete Policy** → policy biến mất khỏi bảng.

**Xác minh bằng CLI:**
```bash
kubectl get varmorpolicy protect-webapp -n default
# → Error from server (NotFound)
```

### Bước 3.8 — Dọn dẹp

```bash
kubectl delete deployment lab03-webapp
```

---

## Lab 04 — Chặn File Nhạy Cảm Qua GUI

### Mục tiêu
Tạo policy với **Banned File Paths** và hiểu cơ chế AppArmor deny rules được sinh ra.

### Lý thuyết ngắn

File `/etc/shadow` chứa password hash của users. Nếu container đọc được file này từ host, attacker có thể crack hash offline. `appArmorRawRules` là cách vArmor nhận raw AppArmor profile fragment để block file access ở kernel level.

### Bước 4.1 — Chuẩn bị target deployment

```bash
# Cần ubuntu để có shell đầy đủ thử nghiệm
kubectl create deployment lab04-target --image=ubuntu:22.04 -- sleep infinity
```

Nhấn **⟳** refresh sidebar → thấy `lab04-target` xuất hiện.

### Bước 4.2 — Tạo policy với Banned Files qua GUI

Điền form **Create VarmorPolicy**:

```
┌──────────────────────────────────────────────────────┐
│ Policy Name: lab04-banned-policy                     │
│ Target:      lab04-target                            │
│                                                      │
│ Enforcers:   [✓] AppArmor                            │
│ Rules:       (để trống)                              │
│                                                      │
│ Banned File Paths:                                   │
│ ┌──────────────────────────────────────────────┐    │
│ │ /etc/shadow                                  │    │
│ │ /etc/passwd                                  │    │
│ │ /proc/sys/kernel/core_pattern                │    │
│ │ /proc/sysrq-trigger                          │    │
│ └──────────────────────────────────────────────┘    │
│                                                      │
│                          [ Apply Policy ]            │
└──────────────────────────────────────────────────────┘
```

**Nhập từng file một dòng** trong textarea "Banned File Paths".

Nhấn **Apply Policy** → thành công.

### Bước 4.3 — Xem AppArmor rule được sinh ra (SSH)

```bash
# Xem raw AppArmor rules được tạo từ banned_files
kubectl get varmorpolicy lab04-banned-policy -n default \
  -o jsonpath='{.spec.policy.enhanceProtect.appArmorRawRules}' \
  | python3 -m json.tool
```

**Output:**
```json
[
    {"rules": "deny /etc/shadow rwmlk,"},
    {"rules": "deny /etc/passwd rwmlk,"},
    {"rules": "deny /proc/sys/kernel/core_pattern rwmlk,"},
    {"rules": "deny /proc/sysrq-trigger rwmlk,"}
]
```

**Giải thích syntax AppArmor:**
- `deny` = cấm tuyệt đối
- `/etc/shadow` = đường dẫn file
- `r` = read, `w` = write, `m` = mmap (load vào memory để chạy), `l` = hard link, `k` = lock
- `,` = dấu kết thúc rule trong AppArmor

**Tại sao GUI nhận danh sách file rồi tự sinh AppArmor syntax?**  
Người dùng không cần biết AppArmor syntax — chỉ cần nhập đường dẫn file. Console "dịch" sang AppArmor format. Đây là lý do tồn tại của abstraction layer.

### Bước 4.4 — Xem toàn bộ policy YAML

Trong bảng **Active Policies**, bạn thấy `lab04-banned-policy`.

Để xem đầy đủ (GUI không có view detail, dùng CLI):
```bash
kubectl describe varmorpolicy lab04-banned-policy -n default
```

### Bước 4.5 — Thử tấn công (nếu varmor-agent đang chạy)

```bash
# Lấy tên pod
POD=$(kubectl get pods -l app=lab04-target -o jsonpath='{.items[0].metadata.name}')

# Kiểm tra agent
kubectl get pods -n varmor -l app=varmor-agent \
  -o jsonpath='{.items[0].status.containerStatuses[0].ready}'
```

Nếu agent ready:
```bash
# Thử đọc /etc/shadow — PHẢI bị chặn
kubectl exec $POD -- cat /etc/shadow
# → cat: /etc/shadow: Permission denied

# Đọc file bình thường — vẫn được
kubectl exec $POD -- cat /etc/hostname
# → (hostname của pod)
```

### Bước 4.6 — So sánh trực quan: có và không có policy

Tạo thêm một deployment không có policy:
```bash
kubectl create deployment lab04-unprotected --image=ubuntu:22.04 -- sleep infinity
POD2=$(kubectl get pods -l app=lab04-unprotected -o jsonpath='{.items[0].metadata.name}')
```

Nhấn **⟳** trên GUI → thấy `lab04-unprotected` xuất hiện với badge ⚠ No Shield.

So sánh:
```bash
# Pod được bảo vệ
echo "=== PROTECTED ==="
kubectl exec $POD -- cat /etc/shadow 2>&1

# Pod không được bảo vệ
echo "=== UNPROTECTED ==="
kubectl exec $POD2 -- cat /etc/shadow 2>&1 | head -3
```

### Bước 4.7 — Dọn dẹp

Nhấn **Delete** trên GUI để xóa `lab04-banned-policy`.

```bash
kubectl delete deployment lab04-target lab04-unprotected
```

Nhấn **⟳** refresh → các deployment biến mất.

---

## Lab 05 — Bảo Vệ Container Escape

### Mục tiêu
Tạo policy dùng **Built-in Defense Rules** cho container escape và privilege escalation.

### Lý thuyết ngắn

**Container Escape**: Thoát khỏi container vào host thông qua lỗ hổng kernel. CVE-2022-0492 là ví dụ nổi tiếng — ghi vào `/proc/sys/kernel/core_pattern` để chạy lệnh trên host khi có process crash.

**Privilege Escalation**: Leo thang từ user thường lên root hoặc từ container namespace sang host namespace.

### Bước 5.1 — Chuẩn bị

```bash
kubectl create deployment lab05-escape-target --image=ubuntu:22.04 -- sleep infinity
kubectl create deployment lab05-priv-target --image=ubuntu:22.04 -- sleep infinity
```

### Bước 5.2 — Tạo policy Container Escape qua GUI

```
┌──────────────────────────────────────────────────────┐
│ Policy Name: lab05-escape-policy                     │
│ Target:      lab05-escape-target                     │
│                                                      │
│ Enforcers:   [✓] AppArmor                            │
│                                                      │
│ Built-in Defense Rules:                              │
│ [✓] Container Escape Prevention    ← TICK CÁI NÀY   │
│ [ ] Privilege Escalation Prevention                  │
│                                                      │
│ Banned File Paths: (để trống)                        │
│                                                      │
│                          [ Apply Policy ]            │
└──────────────────────────────────────────────────────┘
```

Nhấn **Apply Policy**.

### Bước 5.3 — Xem rules được sinh ra (SSH)

```bash
kubectl get varmorpolicy lab05-escape-policy -n default \
  -o jsonpath='{.spec.policy.enhanceProtect.attackProtectionRules}' \
  | python3 -m json.tool
```

**Output:**
```json
[
    {
        "rules": [
            "disallow-write-core-pattern",
            "disallow-mount-securityfs",
            "disallow-write-release-agent"
        ]
    }
]
```

**Tại sao 1 cái checkbox "Container Escape Prevention" sinh ra 3 rules?**  
Đây là sức mạnh của abstraction — người dùng không cần biết tên từng rule kỹ thuật. Console biết `container_escape` maps to danh sách rules nào. Team security cập nhật mapping khi có CVE mới.

### Bước 5.4 — Tạo policy Privilege Escalation qua GUI

```
┌──────────────────────────────────────────────────────┐
│ Policy Name: lab05-priv-policy                       │
│ Target:      lab05-priv-target                       │
│                                                      │
│ Enforcers:   [✓] AppArmor                            │
│                                                      │
│ Built-in Defense Rules:                              │
│ [ ] Container Escape Prevention                      │
│ [✓] Privilege Escalation Prevention  ← TICK CÁI NÀY │
│                                                      │
│                          [ Apply Policy ]            │
└──────────────────────────────────────────────────────┘
```

### Bước 5.5 — Tạo policy kết hợp cả hai

```
┌──────────────────────────────────────────────────────┐
│ Policy Name: lab05-full-protection                   │
│ Target:      lab05-escape-target  (reuse)            │
│                                                      │
│ Built-in Defense Rules:                              │
│ [✓] Container Escape Prevention                      │
│ [✓] Privilege Escalation Prevention  ← CẢ HAI       │
│                                                      │
│ Banned File Paths:                                   │
│ /etc/shadow                                          │
│ /proc/sys/kernel/core_pattern                        │
└──────────────────────────────────────────────────────┘
```

**Lưu ý:** Policy mới tạo ra sẽ conflict với `lab05-escape-policy` trên cùng deployment. Trong K8s, 2 policy cùng target thì cả hai đều được apply (không override nhau).

### Bước 5.6 — Thử tấn công nếu agent sẵn sàng (SSH)

```bash
POD=$(kubectl get pods -l app=lab05-escape-target \
  -o jsonpath='{.items[0].metadata.name}')

# Tấn công core_pattern escape (CVE-2022-0492)
kubectl exec $POD -- sh -c \
  'echo "| /tmp/evil" > /proc/sys/kernel/core_pattern 2>&1'
# Mong đợi: Permission denied

# Tấn công user namespace
kubectl exec $POD -- unshare --user --map-root-user whoami 2>&1
# Mong đợi: Operation not permitted
```

### Bước 5.7 — Quan sát Dashboard: 2 policies cho 1 deployment

Nhìn bảng **Active Policies** — bạn sẽ thấy nhiều dòng:

```
┌─────────────────────┬────────────────────┬───────────┐
│ lab05-escape-policy │ lab05-escape-target│ AppArmor  │
│ lab05-full-protectn │ lab05-escape-target│ AppArmor  │
│ lab05-priv-policy   │ lab05-priv-target  │ AppArmor  │
└─────────────────────┴────────────────────┴───────────┘
```

**Một deployment có thể có nhiều policy không?** Về kỹ thuật có, nhưng rules sẽ overlap — thực tế nên tránh vì khó debug.

### Bước 5.8 — Dọn dẹp qua GUI + CLI

Nhấn **Delete** cho từng policy trong bảng.

```bash
kubectl delete deployment lab05-escape-target lab05-priv-target
```

---

## Lab 06 — Quan Sát Audit Log Real-time

### Mục tiêu
Xem audit log xuất hiện real-time khi thao tác trên GUI, hiểu format và tầm quan trọng.

### Bước 6.1 — Mở 2 cửa sổ song song

**Cửa sổ 1 (Terminal SSH):**
```bash
# Lấy tên console pod
CONSOLE_POD=$(kubectl get pods -l app=armor-pilot \
  -o jsonpath='{.items[0].metadata.name}')

# Follow audit logs real-time
kubectl logs -f $CONSOLE_POD | grep '\[AUDIT\]'
```

Giữ terminal này mở — bạn sẽ thấy log xuất hiện khi thao tác trên GUI.

**Cửa sổ 2 (Browser):**
Mở Console tại `http://172.30.2.129:8080`.

### Bước 6.2 — Tạo policy và quan sát log (GUI)

Chuẩn bị deployment:
```bash
# Terminal khác (Terminal 2):
kubectl create deployment lab06-target --image=nginx:alpine
```

Trên **browser**, tạo policy:
```
Policy Name:  lab06-audit-test
Target:       lab06-target
Enforcers:    [✓] AppArmor
```

Nhấn **Apply Policy**.

**Ngay lập tức** nhìn **Terminal 1** (logs) — bạn sẽ thấy:

```
[2026-05-14T03:15:22Z] [AUDIT] user=admin action=CREATE policy=lab06-audit-test namespace=default status=SUCCESS
```

**Phân tích từng phần:**

```
[2026-05-14T03:15:22Z]              ← timestamp UTC (ISO 8601)
[AUDIT]                             ← marker để grep dễ
user=admin                          ← ai thực hiện (từ Basic Auth header)
action=CREATE                       ← hành động gì
policy=lab06-audit-test             ← tên resource bị tác động
namespace=default                   ← trong namespace nào
status=SUCCESS                      ← kết quả
```

### Bước 6.3 — Tạo trùng tên và xem FAILURE log

Trên browser, tạo lại với cùng tên `lab06-audit-test`:

```
[Apply Policy] ← nhấn lại
```

Bạn sẽ thấy thông báo lỗi trên GUI **và** log trong terminal:

```
[2026-05-14T03:15:35Z] [AUDIT] user=admin action=CREATE policy=lab06-audit-test namespace=default status=FAILURE details="Conflict"
```

**Tại sao log cả FAILURE?** Trong security operations, **attempt thất bại cũng quan trọng**:
- 50 CREATE FAILURE liên tiếp = có thể là bug hoặc attack
- FAILURE với details="Conflict" = có người cố tạo resource trùng
- Audit log là bằng chứng cho incident response

### Bước 6.4 — Xóa policy và xem DELETE log

Nhấn **Delete** → xác nhận trong modal.

Terminal logs:
```
[2026-05-14T03:16:01Z] [AUDIT] user=admin action=DELETE policy=lab06-audit-test namespace=default status=SUCCESS
```

### Bước 6.5 — Lọc và phân tích logs (SSH)

```bash
# Chỉ xem AUDIT events
kubectl logs $CONSOLE_POD | grep '\[AUDIT\]'

# Đếm tổng CREATE actions
kubectl logs $CONSOLE_POD | grep '\[AUDIT\]' | grep 'action=CREATE' | wc -l

# Chỉ xem FAILURE events
kubectl logs $CONSOLE_POD | grep '\[AUDIT\]' | grep 'status=FAILURE'

# Xem logs 10 phút gần nhất
kubectl logs $CONSOLE_POD --since=10m | grep '\[AUDIT\]'

# Timeline hoạt động của user admin
kubectl logs $CONSOLE_POD | grep '\[AUDIT\]' | grep 'user=admin' | \
  awk '{print $1, $5, $6, $9}' | tail -20
```

### Bước 6.6 — Hiểu Gunicorn access log

Ngoài audit log, còn có HTTP access log:
```bash
kubectl logs $CONSOLE_POD | grep -v '\[AUDIT\]' | grep -E 'POST|DELETE|GET' | tail -10
```

Output:
```
127.0.0.1 - admin [14/May/2026:03:15:22 +0000] "POST /api/policies HTTP/1.1" 201 105
127.0.0.1 - admin [14/May/2026:03:16:01 +0000] "DELETE /api/.../lab06-audit-test HTTP/1.1" 200 60
```

**Hai loại log này bổ sung nhau:**
- **Access log**: HTTP method, URL, status code, bytes — cho debugging và performance
- **Audit log**: user, action, resource, outcome — cho security và compliance

### Bước 6.7 — Dọn dẹp

```bash
kubectl delete deployment lab06-target
```

---

## Lab 07 — Xác Minh RBAC & Phân Quyền

### Mục tiêu
Hiểu Console đang chạy với quyền gì, tại sao đó là quyền tối thiểu đủ dùng, và tác động nếu bị compromise.

### Bước 7.1 — Xem Console đang chạy với ServiceAccount nào (GUI ngắn gọn)

Dashboard không hiện ServiceAccount info trực tiếp. Dùng CLI:

```bash
kubectl get pods -l app=armor-pilot \
  -o jsonpath='{.items[0].spec.serviceAccountName}'
# → armor-pilot-sa
```

### Bước 7.2 — Hiểu ClusterRole của Console

```bash
kubectl get clusterrole armor-pilot-role -o yaml
```

**Đọc và hiểu từng rule:**
```yaml
rules:
# Rule 1: Chỉ ĐỌC deployments
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch"]
  # → Sidebar Deployments cần quyền này
  # → KHÔNG có "create","delete","update" → không thể sửa deployment

# Rule 2: Toàn quyền VarmorPolicy
- apiGroups: ["crd.varmor.org"]
  resources: ["varmorpolicies"]
  verbs: ["get","list","watch","create","update","patch","delete"]
  # → Cần cho tất cả chức năng Create/Delete Policy trên GUI
```

**Tại sao không cấp quyền đọc Secrets?** Console cần password từ Secret khi khởi động — nhưng K8s inject Secret vào env var, không cần Console tự đọc Secret API.

### Bước 7.3 — Test quyền thực tế

```bash
SA="system:serviceaccount:default:armor-pilot-sa"

echo "=== QUYỀN ĐƯỢC PHÉP (phải là 'yes') ==="
kubectl auth can-i get deployments --as="$SA" --all-namespaces
kubectl auth can-i list deployments --as="$SA" --all-namespaces
kubectl auth can-i create varmorpolicies.crd.varmor.org --as="$SA" --all-namespaces
kubectl auth can-i delete varmorpolicies.crd.varmor.org --as="$SA" --all-namespaces

echo ""
echo "=== QUYỀN BỊ CẤM (phải là 'no') ==="
kubectl auth can-i delete deployments --as="$SA" --all-namespaces
kubectl auth can-i get secrets --as="$SA" --all-namespaces
kubectl auth can-i create pods --as="$SA" --all-namespaces
kubectl auth can-i delete namespaces --as="$SA" --all-namespaces
kubectl auth can-i get clusterroles --as="$SA" --all-namespaces
```

### Bước 7.4 — Kiểm tra security context container (không hiện trên GUI)

```bash
kubectl get pods -l app=armor-pilot -o json | python3 -c "
import sys, json
pod = json.load(sys.stdin)['items'][0]
c = pod['spec']['containers'][0]
sc = c.get('securityContext', {})
print('Container Security Context:')
print('  runAsUser:', sc.get('runAsUser'))
print('  runAsNonRoot:', sc.get('runAsNonRoot'))
print('  allowPrivilegeEscalation:', sc.get('allowPrivilegeEscalation'))
print('  capabilities.drop:', sc.get('capabilities', {}).get('drop'))
"
```

**Output:**
```
Container Security Context:
  runAsUser: 999
  runAsNonRoot: True
  allowPrivilegeEscalation: False
  capabilities.drop: ['ALL']
```

**Ý nghĩa từng dòng:**

| Setting | Giá trị | Bảo vệ chống gì |
|---|---|---|
| `runAsUser: 999` | UID 999 (non-root) | Process không có quyền root mặc định |
| `runAsNonRoot: True` | K8s từ chối nếu image root | Kiểm tra tại admission time |
| `allowPrivilegeEscalation: False` | Không được sudo/setuid | Chặn leo thang đặc quyền |
| `capabilities.drop: ALL` | Drop tất cả Linux caps | Tước quyền kernel đặc biệt |

### Bước 7.5 — Scenario: nếu Console bị compromise

**Tình huống:** Attacker khai thác lỗ hổng trong Flask app và có shell trong Console container.

**Với RBAC hiện tại, attacker chỉ có thể:**
```bash
# ✅ Liệt kê deployments
kubectl get deployments -A

# ✅ Xem/tạo/xóa VarmorPolicy
kubectl get varmorpolicies -A
kubectl delete varmorpolicy ten-policy -n ns   # ← nguy hiểm: xóa protection!
```

**Attacker KHÔNG THỂ:**
```bash
# ❌ Đọc Secrets (credentials của service khác)
kubectl get secrets -A    # → Forbidden

# ❌ Tạo Pod để pivot
kubectl run evil --image=ubuntu    # → Forbidden

# ❌ Xem ClusterRole để plan privilege escalation
kubectl get clusterroles    # → Forbidden
```

**Bài học:** RBAC không phải magic bullet — nếu bị compromise, attacker vẫn có thể xóa policy bảo vệ. Nhưng RBAC giới hạn **blast radius**: thay vì mất toàn bộ cluster, chỉ mất policy management.

### Bước 7.6 — Kiểm tra pod dùng đúng SA từ GUI → CLI

Trên GUI, đảm bảo Console đang chạy:
```bash
# Deployment spec có ServiceAccount
kubectl get deployment armor-pilot \
  -o jsonpath='{.spec.template.spec.serviceAccountName}'
# → armor-pilot-sa
```

---

## Phần Tổng Kết

### Những gì bạn vừa học được

| Lab | Làm gì trên GUI | Kiểm chứng bằng CLI | Khái niệm bảo mật |
|---|---|---|---|
| 01 | Đăng nhập sai / đúng | `curl` không có auth | Basic Auth, user enumeration |
| 02 | Đọc badge Protected / No Shield | `kubectl label` | K8s labels, vArmor detection |
| 03 | Tạo / Xóa policy đơn giản | `kubectl get varmorpolicy` | CRD, K8s as source of truth |
| 04 | Nhập Banned File Paths | Xem `appArmorRawRules` | AppArmor deny syntax, /proc/* |
| 05 | Tick checkboxes Defense Rules | Xem `attackProtectionRules` | Container escape, CVE-2022-0492 |
| 06 | Mọi thao tác + xem log real-time | `kubectl logs \| grep AUDIT` | Audit trail, incident response |
| 07 | (GUI không hiện trực tiếp) | `kubectl auth can-i` | RBAC, least privilege |

### GUI làm gì, CLI làm gì

```
┌──────────────────────────────────────────────────────────┐
│  GUI (browser)          CLI (kubectl)                    │
│  ─────────────────       ───────────────                 │
│  Tạo policy             Xác minh CRD thật                │
│  Xóa policy             Đọc raw YAML spec               │
│  Xem deployment list    Test RBAC với auth can-i         │
│  Xem policy table       Follow logs real-time            │
│  Form validation        Thử tấn công thực tế            │
│                         Debug khi GUI không show đủ     │
└──────────────────────────────────────────────────────────┘
```

GUI là công cụ **quản lý hàng ngày** — nhanh, trực quan. CLI là công cụ **kiểm chứng và debug** — chính xác, không trừu tượng hóa.

### Câu hỏi suy nghĩ thêm

1. Dashboard không có tính năng "Edit Policy" (chỉ Create và Delete). **Tại sao** design vậy thay vì cho phép edit?
2. Nếu bạn xóa một VarmorPolicy, container đang chạy có **ngay lập tức** mất bảo vệ không?
3. Audit log lưu ở đâu nếu pod bị restart? Làm sao để **không mất** log?
4. Badge "Protected" trên GUI có thể hiển thị **sai** không? Trong tình huống nào?
5. Tại sao không có tính năng "View Policy Details" trên GUI — bạn phải dùng kubectl?

---

*Guide này thiết kế để dùng song song: một tab browser mở Console, một terminal SSH vào server. Làm trên GUI trước để hiểu flow, dùng CLI để đào sâu và kiểm chứng.*
