# Thực Hành Bảo Mật Container với vArmor
## 5 Labs Tấn Công & Phòng Thủ Thực Tế

> **Phiên bản:** 1.0 | **Cập nhật:** 2026-05-15
> **Console:** `http://<server-address>:30080` | **Tài khoản:** `admin / <configured-admin-password>`
> **SSH vào server:** `ssh root@<server-address>` bằng SSH key; không lưu password trong tài liệu hoặc source control.
> **Triết lý:** Web UI để áp dụng bảo vệ → CLI để tấn công và kiểm chứng → Hiểu tại sao

---

## Mục Lục

| Lab | Chủ đề | Kỹ thuật bảo vệ | Thời gian |
|-----|--------|-----------------|-----------|
| [Lab 1](#lab-1-ngăn-chặn-đánh-cắp-thông-tin-nhạy-cảm) | Ngăn đánh cắp thông tin nhạy cảm | Banned File Paths (AppArmor) | ~20 phút |
| [Lab 2](#lab-2-ngăn-chặn-container-escape) | Ngăn Container Escape | Built-in rule: container_escape | ~25 phút |
| [Lab 3](#lab-3-chống-leo-thang-đặc-quyền) | Chống leo thang đặc quyền | Built-in rule: privilege_escalation | ~20 phút |
| [Lab 4](#lab-4-bảo-vệ-ứng-dụng-đa-lớp) | Bảo vệ ứng dụng đa lớp | Kết hợp tất cả (AppArmor + Seccomp) | ~30 phút |
| [Lab 5](#lab-5-quản-lý-và-kiểm-soát-chính-sách) | Quản lý và kiểm soát chính sách | Policy lifecycle + Audit trail | ~25 phút |

---

## Kiến Thức Nền Tảng

### Tại sao container isolation không đủ?

Kubernetes namespace và cgroup cô lập tài nguyên (CPU, memory, network...) nhưng **không chặn syscall nguy hiểm**. Một container mặc định có thể:

```
Container Process
      │
      ▼
   syscall (open, write, unshare, mount...)
      │
      ▼ ← không có filter nào ở đây!
  Linux Kernel
      │
      ▼
   Hardware / Host
```

**vArmor** thêm AppArmor/Seccomp/eBPF hooks vào đây:

```
Container Process
      │
      ▼
   syscall attempt
      │
      ▼
[AppArmor LSM hook] ← vArmor profile được load ở đây
      │
      ├── ALLOWED → thực hiện
      └── DENIED  → trả EPERM (Permission denied)
```

### Luồng hoạt động của ArmorPilot

```
1. Tạo policy trên Web UI
        │
        ▼
2. Console gọi K8s API → tạo VarmorPolicy CRD
        │
        ▼
3. vArmor manager biên dịch → AppArmor profile
        │
        ▼
4. vArmor agent load profile vào kernel (~15 giây)
        │
        ▼
5. Label deployment: sandbox.varmor.org/enable=true
        │
        ▼
6. Webhook inject annotation vào Pod mới
        │
        ▼
7. Pod mới được kernel enforce theo profile
```

### Quy tắc quan trọng: thứ tự thực hiện

```
ĐÚNG:  Tạo policy → Label deployment → Restart pods → Kiểm tra
SAI:   Label deployment → Tạo policy  (pods cũ không có profile!)
```

---

## Lab 1: Ngăn Chặn Đánh Cắp Thông Tin Nhạy Cảm

### Bối cảnh

Công ty bạn deploy một web service trong Kubernetes. Một lỗ hổng trong ứng dụng cho phép attacker thực thi lệnh tùy ý bên trong container (Remote Code Execution). Attacker khai thác để đọc file `/etc/shadow`, `/etc/passwd`, và các key nhạy cảm từ kernel — chuẩn bị cho bước tấn công tiếp theo.

Bạn cần áp dụng policy để ngăn container đọc những file này, dù attacker đã có shell bên trong.

### Mục tiêu

- Chứng minh container mặc định có thể đọc file nhạy cảm
- Tạo policy Banned File Paths qua Web UI
- Xác minh AppArmor deny rule được sinh ra trong CRD
- Chứng minh policy thực sự chặn việc đọc file sau khi áp dụng

---

### Phần 1: Chuẩn Bị Môi Trường

SSH vào server và tạo deployment mục tiêu:

```bash
ssh root@<server-address>

# Tạo deployment giả lập web server bị tấn công
kubectl create deployment lab1-webapp --image=ubuntu:22.04 -- sleep infinity

# Chờ pod khởi động
kubectl rollout status deployment/lab1-webapp

# Lấy tên pod để dùng trong các bước sau
POD1=$(kubectl get pods -l app=lab1-webapp -o jsonpath='{.items[0].metadata.name}')
echo "Pod name: $POD1"
```

**Kết quả mong đợi:**
```
deployment.apps/lab1-webapp created
Waiting for deployment "lab1-webapp" rollout to finish: 0 of 1 updated replicas are available...
deployment "lab1-webapp" successfully rolled out
Pod name: lab1-webapp-7d9f8b6c4-xk2mp
```

---

### Phần 2: Tấn Công Không Có Bảo Vệ

Mô phỏng attacker đã vào được container, đọc thông tin nhạy cảm:

```bash
# Đọc /etc/shadow — chứa password hash của các user
kubectl exec $POD1 -- cat /etc/shadow

# Đọc /etc/passwd — liệt kê tất cả user và UID
kubectl exec $POD1 -- cat /etc/passwd | head -5

# Đọc kernel process key
kubectl exec $POD1 -- cat /proc/keys 2>/dev/null || echo "(procfs keys not accessible)"

# Đọc file môi trường (có thể chứa secrets)
kubectl exec $POD1 -- cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | head -10
```

**Kết quả mong đợi — TẤN CÔNG THÀNH CÔNG (chưa có bảo vệ):**
```
root:$6$rounds=5000$salt$CfS8txqPAtDZ...:19000:0:99999:7:::
daemon:*:18375:0:99999:7:::
bin:*:18375:0:99999:7:::

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev/null:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=lab1-webapp-7d9f8b6c4-xk2mp
```

**Ý nghĩa:** Attacker có hash password — có thể crack offline bằng hashcat. File `/etc/passwd` cho biết danh sách user để brute-force login.

---

### Phần 3: Áp Dụng Bảo Vệ Qua Console

**Bước 3.1 — Mở Console trên trình duyệt:**

```
http://<server-address>:30080
Username: admin
Password: <configured-admin-password>
```

**Bước 3.2 — Nhấn "Load" để tải danh sách deployment:**

Nhấn nút **Load** ở header. Sidebar phải hiện `lab1-webapp` với badge **No Shield**.

**Bước 3.3 — Điền form Create Policy như sau:**

```
┌──────────────────────────────────────────────────────────────┐
│  Create VarmorPolicy                                         │
│                                                              │
│  Policy Name *               Target Deployment *             │
│  ┌─────────────────────┐    ┌──────────────────────────┐    │
│  │ lab1-sensitive-files│    │ ▼ lab1-webapp            │    │
│  └─────────────────────┘    └──────────────────────────┘    │
│                                                              │
│  Kernel Enforcers:                                           │
│  [✓] AppArmor   [ ] Seccomp   [ ] BPF                       │
│                                                              │
│  Built-in Defense Rules:                                     │
│  [ ] Container Escape Prevention                             │
│  [ ] Privilege Escalation Prevention                         │
│                                                              │
│  Banned File Paths (one per line):                           │
│  ┌────────────────────────────────────────────────────┐     │
│  │ /etc/shadow                                        │     │
│  │ /etc/passwd                                        │     │
│  │ /proc/keys                                         │     │
│  │ /proc/sys/kernel/dmesg                             │     │
│  └────────────────────────────────────────────────────┘     │
│                                                              │
│                              [ Apply Policy ]                │
└──────────────────────────────────────────────────────────────┘
```

**Điền chính xác:**
- **Policy Name:** `lab1-sensitive-files`
- **Target Deployment:** chọn `lab1-webapp` từ dropdown
- **Kernel Enforcers:** chỉ tick `AppArmor`
- **Built-in Defense Rules:** để trống tất cả
- **Banned File Paths:** nhập từng dòng: `/etc/shadow`, `/etc/passwd`, `/proc/keys`, `/proc/sys/kernel/dmesg`

Nhấn **Apply Policy** → thông báo xanh xuất hiện.

**Bước 3.4 — Chờ agent load profile (CLI):**

```bash
# Kiểm tra policy đã được tạo trong K8s
kubectl get varmorpolicy lab1-sensitive-files -n default

# Xem AppArmor rules được sinh ra từ banned files
kubectl get varmorpolicy lab1-sensitive-files -n default \
  -o jsonpath='{.spec.policy.enhanceProtect.appArmorRawRules}' \
  | python3 -m json.tool

# Chờ 15 giây để varmor-agent load profile vào kernel
echo "Waiting 15s for agent to load AppArmor profile..."
sleep 15

# Kiểm tra policy đã Ready chưa
kubectl get varmorpolicy lab1-sensitive-files -n default \
  -o jsonpath='{.status.phase}'
```

**Kết quả mong đợi:**
```json
[
  {"rules": "deny /etc/shadow rwmlk,"},
  {"rules": "deny /etc/passwd rwmlk,"},
  {"rules": "deny /proc/keys rwmlk,"},
  {"rules": "deny /proc/sys/kernel/dmesg rwmlk,"}
]
```

**Giải thích AppArmor syntax:** `deny /etc/shadow rwmlk,` nghĩa là cấm tuyệt đối mọi thao tác `r`ead, `w`rite, `m`map, `l`ink, `k`lock trên file này. Dấu `,` là cú pháp bắt buộc của AppArmor.

**Bước 3.5 — Gắn label và restart pods:**

```bash
# Gắn label để webhook inject AppArmor annotation
kubectl label deployment lab1-webapp sandbox.varmor.org/enable=true

# Restart pods để tạo pods mới với annotation
kubectl rollout restart deployment/lab1-webapp

# Chờ pod mới sẵn sàng
kubectl rollout status deployment/lab1-webapp

# Lấy tên pod mới
POD1=$(kubectl get pods -l app=lab1-webapp -o jsonpath='{.items[0].metadata.name}')
echo "New pod: $POD1"

# Xác nhận pod mới có AppArmor annotation
kubectl get pod $POD1 -o jsonpath='{.metadata.annotations}' | python3 -m json.tool
```

**Kết quả mong đợi — annotation được inject:**
```json
{
  "container.apparmor.security.beta.kubernetes.io/lab1-webapp": "localhost/varmor-default-lab1-sensitive-files"
}
```

---

### Phần 4: Kiểm Tra Bảo Vệ

Chạy lại đúng các cuộc tấn công từ Phần 2:

```bash
# Thử đọc /etc/shadow — PHẢI BỊ CHẶN
echo "=== Test 1: /etc/shadow ==="
kubectl exec $POD1 -- cat /etc/shadow

echo ""
echo "=== Test 2: /etc/passwd ==="
kubectl exec $POD1 -- cat /etc/passwd

echo ""
echo "=== Test 3: /proc/keys ==="
kubectl exec $POD1 -- cat /proc/keys

echo ""
echo "=== Test 4: Kiểm tra file BÌNH THƯỜNG vẫn đọc được ==="
kubectl exec $POD1 -- cat /etc/hostname
kubectl exec $POD1 -- cat /etc/os-release | head -3
```

**Kết quả mong đợi — BẢO VỆ HOẠT ĐỘNG:**
```
=== Test 1: /etc/shadow ===
cat: /etc/shadow: Permission denied

=== Test 2: /etc/passwd ===
cat: /etc/passwd: Permission denied

=== Test 3: /proc/keys ===
cat: /proc/keys: Permission denied

=== Test 4: Kiểm tra file BÌNH THƯỜNG vẫn đọc được ===
lab1-webapp-6b8f9c7d5-m3nqp
PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
```

**Tại sao điều này hoạt động ở kernel level?** AppArmor là Linux Security Module (LSM). Khi process trong container gọi syscall `open("/etc/shadow", O_RDONLY)`, kernel hooks vào LSM check point và tham chiếu profile đang active. Profile có rule `deny /etc/shadow r` → kernel trả về `EPERM` (-1, errno 13) trước khi file được mở. Ngay cả root trong container cũng không thể bypass vì AppArmor kiểm tra ở kernel level, không phải user-space.

---

### Phần 5: Dọn Dẹp

```bash
# Xóa policy qua Console: nhấn Delete trong bảng Active Policies → xác nhận

# Hoặc xóa bằng CLI:
kubectl delete varmorpolicy lab1-sensitive-files -n default

# Xóa deployment
kubectl delete deployment lab1-webapp

# Xác nhận đã dọn sạch
kubectl get varmorpolicy -n default
kubectl get deployment lab1-webapp 2>&1
```

---

### Câu Hỏi Tự Học

1. AppArmor check quyền của process dựa trên **profile name** được gắn vào pod annotation. Nếu attacker có thể sửa annotation của pod, họ có thể bypass protection không? Tại sao có/không?

2. Policy này chặn `/etc/shadow` trong container. Nhưng nếu container mount host path `/etc` vào `/host-etc`, file `/host-etc/shadow` có bị chặn không? Tại sao?

3. Tại sao `deny /etc/shadow rwmlk,` bao gồm cả `m` (mmap) và `k` (lock), không chỉ `r` (read)? Kịch bản tấn công nào dùng mmap để đọc file?

4. Thêm `/proc/1/environ` vào banned files có ngăn attacker đọc environment variables (secrets) của process PID 1 không? Tại sao đây là vector tấn công quan trọng?

---

## Lab 2: Ngăn Chặn Container Escape

### Bối cảnh

Một container trong production cluster bị compromised bởi CVE trong ứng dụng. Attacker có shell root bên trong container và muốn "thoát" ra host node để kiểm soát toàn bộ cluster. Kỹ thuật phổ biến nhất là ghi vào `/proc/sys/kernel/core_pattern` (CVE-2022-0492) — một kernel parameter **không được namespaced**, cho phép chạy lệnh tùy ý trên HOST khi có process crash.

Bạn cần áp dụng `container_escape` protection rule để ngăn kỹ thuật này.

### Mục tiêu

- Hiểu cơ chế CVE-2022-0492 và tại sao nó nguy hiểm
- Chứng minh ghi `core_pattern` thành công khi không có protection
- Áp dụng `Container Escape Prevention` rule qua Web UI
- Xác minh việc ghi bị chặn sau khi áp dụng policy

---

### Phần 1: Chuẩn Bị Môi Trường

```bash
ssh root@<server-address>

# Tạo deployment mô phỏng container bị compromised
kubectl create deployment lab2-compromised --image=ubuntu:22.04 -- sleep infinity

# Chờ pod khởi động
kubectl rollout status deployment/lab2-compromised

# Lấy tên pod
POD2=$(kubectl get pods -l app=lab2-compromised -o jsonpath='{.items[0].metadata.name}')
echo "Pod: $POD2"

# Kiểm tra container đang chạy với user gì
kubectl exec $POD2 -- id
```

**Kết quả mong đợi:**
```
deployment.apps/lab2-compromised created
deployment "lab2-compromised" successfully rolled out
Pod: lab2-compromised-5c6d7e8f9-p4qrs
uid=0(root) gid=0(root) groups=0(root)
```

**Lưu ý:** Container đang chạy với UID 0 (root trong container). Đây là default nguy hiểm mà nhiều team không để ý.

---

### Phần 2: Tấn Công Không Có Bảo Vệ

Mô phỏng kỹ thuật container escape CVE-2022-0492:

```bash
# Bước 1: Đọc core_pattern hiện tại
echo "--- Giá trị core_pattern hiện tại ---"
kubectl exec $POD2 -- cat /proc/sys/kernel/core_pattern

# Bước 2: Thử ghi vào core_pattern (vector tấn công chính)
echo "--- Thử ghi core_pattern ---"
kubectl exec $POD2 -- sh -c 'echo "| /tmp/evil_script %s" > /proc/sys/kernel/core_pattern 2>&1'

# Bước 3: Kiểm tra xem ghi có thành công không
echo "--- Kiểm tra core_pattern sau khi ghi ---"
kubectl exec $POD2 -- cat /proc/sys/kernel/core_pattern

# Bước 4: Thử tạo file thực thi giả (script escape)
echo "--- Tạo script escape giả ---"
kubectl exec $POD2 -- sh -c 'echo "#!/bin/bash\nid > /tmp/pwned_by_escape" > /tmp/evil_script && chmod +x /tmp/evil_script'
kubectl exec $POD2 -- ls -la /tmp/
```

**Kết quả mong đợi — TẤN CÔNG THÀNH CÔNG (chưa có bảo vệ):**
```
--- Giá trị core_pattern hiện tại ---
core

--- Thử ghi core_pattern ---
(không có lỗi — ghi thành công!)

--- Kiểm tra core_pattern sau khi ghi ---
| /tmp/evil_script %s

--- Tạo script escape giả ---
total 16
drwxrwxrwt 1 root root 4096 May 15 09:23 .
drwxr-xr-x 1 root root 4096 May 14 00:00 ..
-rwxr-xr-x 1 root root   47 May 15 09:23 evil_script
```

**Giải thích nguy hiểm:** `core_pattern` với prefix `|` nghĩa là "khi có process crash, hãy pipe core dump vào chương trình này". Vì `core_pattern` là kernel parameter toàn cục (không bị namespaced), nó ảnh hưởng đến TOÀN BỘ HOST. Bất kỳ process nào crash trên host hoặc container khác đều sẽ trigger `/tmp/evil_script` chạy với quyền root trên HOST, không phải trong container.

**Đặt lại core_pattern về mặc định:**
```bash
# Reset để không ảnh hưởng host thật
kubectl exec $POD2 -- sh -c 'echo "core" > /proc/sys/kernel/core_pattern'
echo "Reset xong: $(kubectl exec $POD2 -- cat /proc/sys/kernel/core_pattern)"
```

---

### Phần 3: Áp Dụng Bảo Vệ Qua Console

**Bước 3.1 — Mở Console:**
```
http://<server-address>:30080
```

**Bước 3.2 — Nhấn Load để tải deployment list.**

**Bước 3.3 — Điền form Create Policy:**

```
┌──────────────────────────────────────────────────────────────┐
│  Create VarmorPolicy                                         │
│                                                              │
│  Policy Name *               Target Deployment *             │
│  ┌─────────────────────┐    ┌──────────────────────────┐    │
│  │ lab2-escape-prevent │    │ ▼ lab2-compromised       │    │
│  └─────────────────────┘    └──────────────────────────┘    │
│                                                              │
│  Kernel Enforcers:                                           │
│  [✓] AppArmor   [ ] Seccomp   [ ] BPF                       │
│                                                              │
│  Built-in Defense Rules:                                     │
│  [✓] Container Escape Prevention    ← TICK CÁI NÀY          │
│  [ ] Privilege Escalation Prevention                         │
│                                                              │
│  Banned File Paths (one per line):                           │
│  ┌────────────────────────────────────────────────────┐     │
│  │ (để trống)                                         │     │
│  └────────────────────────────────────────────────────┘     │
│                                                              │
│                              [ Apply Policy ]                │
└──────────────────────────────────────────────────────────────┘
```

**Điền chính xác:**
- **Policy Name:** `lab2-escape-prevent`
- **Target Deployment:** `lab2-compromised`
- **Kernel Enforcers:** `AppArmor`
- **Built-in Defense Rules:** tick **Container Escape Prevention**
- **Banned File Paths:** để trống

Nhấn **Apply Policy**.

**Bước 3.4 — Xem rules được sinh ra (CLI):**

```bash
# Xem attack protection rules được tạo từ container_escape
kubectl get varmorpolicy lab2-escape-prevent -n default \
  -o jsonpath='{.spec.policy.enhanceProtect.attackProtectionRules}' \
  | python3 -m json.tool
```

**Kết quả mong đợi:**
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

**Giải thích từng rule:**
- `disallow-write-core-pattern`: Chặn ghi vào `/proc/sys/kernel/core_pattern` — vector CVE-2022-0492
- `disallow-mount-securityfs`: Chặn mount `securityfs` — expose AppArmor admin interface cho attacker
- `disallow-write-release-agent`: Chặn ghi `release_agent` trong cgroup hierarchy — variant escape khác

**Bước 3.5 — Gắn label và restart pods:**

```bash
# Chờ agent load profile
sleep 15

# Gắn label cho deployment
kubectl label deployment lab2-compromised sandbox.varmor.org/enable=true

# Restart để pod mới nhận annotation
kubectl rollout restart deployment/lab2-compromised
kubectl rollout status deployment/lab2-compromised

# Lấy tên pod mới
POD2=$(kubectl get pods -l app=lab2-compromised -o jsonpath='{.items[0].metadata.name}')
echo "New pod: $POD2"
```

---

### Phần 4: Kiểm Tra Bảo Vệ

```bash
# Test 1: Ghi core_pattern — PHẢI BỊ CHẶN
echo "=== Test 1: Ghi core_pattern ==="
kubectl exec $POD2 -- sh -c 'echo "| /tmp/evil" > /proc/sys/kernel/core_pattern 2>&1'
echo "Exit code: $?"

# Test 2: Kiểm tra core_pattern KHÔNG bị thay đổi
echo ""
echo "=== Test 2: Kiểm tra core_pattern không đổi ==="
kubectl exec $POD2 -- cat /proc/sys/kernel/core_pattern

# Test 3: Thử mount securityfs — PHẢI BỊ CHẶN
echo ""
echo "=== Test 3: Mount securityfs ==="
kubectl exec $POD2 -- mount -t securityfs securityfs /tmp/sf 2>&1

# Test 4: Thử ghi release_agent — PHẢI BỊ CHẶN
echo ""
echo "=== Test 4: Ghi release_agent (nếu có cgroup fs) ==="
kubectl exec $POD2 -- sh -c 'cat /proc/mounts | grep cgroup | head -3'
kubectl exec $POD2 -- sh -c 'find /sys/fs/cgroup -name release_agent 2>/dev/null | head -1 | xargs -I{} sh -c "echo test > {} 2>&1"'

# Test 5: Ghi bình thường vẫn hoạt động
echo ""
echo "=== Test 5: Ghi file BÌNH THƯỜNG vẫn được ==="
kubectl exec $POD2 -- sh -c 'echo "hello" > /tmp/normal_file && cat /tmp/normal_file'
```

**Kết quả mong đợi — BẢO VỆ HOẠT ĐỘNG:**
```
=== Test 1: Ghi core_pattern ===
sh: echo: write error: Permission denied
Exit code: 1

=== Test 2: Kiểm tra core_pattern không đổi ===
core

=== Test 3: Mount securityfs ===
mount: /tmp/sf: permission denied.

=== Test 4: Ghi release_agent (nếu có cgroup fs) ===
(permission denied hoặc không tìm thấy release_agent)

=== Test 5: Ghi file BÌNH THƯỜNG vẫn được ===
hello
```

**Tại sao `disallow-write-core-pattern` hoạt động?** `/proc/sys/kernel/core_pattern` là một procfs entry đặc biệt. Khi AppArmor profile có rule cho path này, kernel hook `file_permission` trong LSM intercepted mọi syscall `write()` hoặc `open(O_WRONLY)` tới path này — bất kể process đang chạy với UID nào, kể cả UID 0 (root trong container).

---

### Phần 5: Dọn Dẹp

```bash
# Xóa policy qua Console (nhấn Delete) hoặc CLI:
kubectl delete varmorpolicy lab2-escape-prevent -n default

# Xóa deployment
kubectl delete deployment lab2-compromised

# Verify
kubectl get varmorpolicy -n default | grep lab2
kubectl get deployment lab2-compromised 2>&1
```

---

### Câu Hỏi Tự Học

1. `/proc/sys/kernel/core_pattern` là kernel parameter KHÔNG bị namespaced. Liệt kê 3 kernel parameter quan trọng khác không bị namespaced và giải thích tại sao đây là attack surface nguy hiểm.

2. Rule `disallow-mount-securityfs` ngăn mount `securityfs`. Tại sao attacker muốn mount `securityfs`? Họ có thể làm gì với AppArmor admin interface nếu vào được?

3. CVE-2022-0492 yêu cầu container phải có `CAP_SYS_ADMIN` capability. Nếu container KHÔNG có capability này, cuộc tấn công có thể thực hiện không? AppArmor rule và Linux capabilities bổ sung nhau như thế nào?

4. Nếu attacker không thể ghi `core_pattern`, họ có thể dùng cách nào khác để escape container? Nghiên cứu về "dirty cow" (CVE-2016-5195) và "runc exploit" (CVE-2019-5736).

---

## Lab 3: Chống Leo Thang Đặc Quyền

### Bối cảnh

Attacker đã vào được container đang chạy với user thường (non-root). Họ tìm cách leo thang lên quyền cao hơn bằng kỹ thuật **user namespace abuse** — tạo user namespace mới để "giả vờ" là root, sau đó khai thác các kernel feature chỉ dành cho privileged process. Kỹ thuật này là bước đệm phổ biến trong chuỗi tấn công privilege escalation.

Bạn cần áp dụng `privilege_escalation` protection rule để chặn việc tạo user namespace và disable các Linux capability nguy hiểm.

### Mục tiêu

- Hiểu user namespace là gì và tại sao nó là attack vector
- Chứng minh `unshare --user` hoạt động khi không có protection
- Áp dụng `Privilege Escalation Prevention` rule qua Web UI
- Xác minh `unshare` bị chặn sau khi áp dụng policy

---

### Phần 1: Chuẩn Bị Môi Trường

```bash
ssh root@<server-address>

# Tạo deployment với user thường (non-root) để mô phỏng thực tế hơn
kubectl create deployment lab3-restricted --image=ubuntu:22.04 -- sleep infinity

# Chờ pod khởi động
kubectl rollout status deployment/lab3-restricted

# Lấy tên pod
POD3=$(kubectl get pods -l app=lab3-restricted -o jsonpath='{.items[0].metadata.name}')
echo "Pod: $POD3"

# Cài unshare tool (trong ubuntu image)
kubectl exec $POD3 -- apt-get update -qq 2>/dev/null
kubectl exec $POD3 -- apt-get install -y -qq util-linux 2>/dev/null
echo "Setup done"
```

---

### Phần 2: Tấn Công Không Có Bảo Vệ

```bash
# Kiểm tra user hiện tại
echo "=== User hiện tại ==="
kubectl exec $POD3 -- id

# Bước tấn công 1: Tạo user namespace mới và map thành root
echo ""
echo "=== Tấn công: unshare user namespace ==="
kubectl exec $POD3 -- unshare --user --map-root-user id

# Bước tấn công 2: Tạo user namespace và chạy shell
echo ""
echo "=== Kiểm tra capabilities trong namespace mới ==="
kubectl exec $POD3 -- unshare --user --map-root-user sh -c 'id && cat /proc/self/status | grep "^Cap"'

# Bước tấn công 3: Thử exploit kết hợp — user ns + pid ns
echo ""
echo "=== Thử kết hợp namespaces ==="
kubectl exec $POD3 -- unshare --user --map-root-user --pid --fork id 2>&1
```

**Kết quả mong đợi — TẤN CÔNG THÀNH CÔNG (chưa có bảo vệ):**
```
=== User hiện tại ===
uid=0(root) gid=0(root) groups=0(root)

=== Tấn công: unshare user namespace ===
uid=0(root) gid=0(root) groups=0(root)

=== Kiểm tra capabilities trong namespace mới ===
uid=0(root) gid=0(root) groups=0(root)
CapInh: 0000000000000000
CapPrm: 000001ffffffffff
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
```

**Giải thích nguy hiểm:** Trong user namespace mới, process "thấy" mình là UID 0 với **đầy đủ capabilities** (CapEff: `000001ffffffffff` = tất cả ~41 capabilities). Mặc dù đây là "fake root" trong namespace, nhiều kernel code path không check đủ boundary → là stepping stone cho các kernel exploit.

---

### Phần 3: Áp Dụng Bảo Vệ Qua Console

**Bước 3.1 — Mở Console:** `http://<server-address>:30080`

**Bước 3.2 — Nhấn Load.**

**Bước 3.3 — Điền form Create Policy:**

```
┌──────────────────────────────────────────────────────────────┐
│  Create VarmorPolicy                                         │
│                                                              │
│  Policy Name *               Target Deployment *             │
│  ┌─────────────────────┐    ┌──────────────────────────┐    │
│  │ lab3-privesc-block  │    │ ▼ lab3-restricted        │    │
│  └─────────────────────┘    └──────────────────────────┘    │
│                                                              │
│  Kernel Enforcers:                                           │
│  [✓] AppArmor   [ ] Seccomp   [ ] BPF                       │
│                                                              │
│  Built-in Defense Rules:                                     │
│  [ ] Container Escape Prevention                             │
│  [✓] Privilege Escalation Prevention  ← TICK CÁI NÀY        │
│                                                              │
│  Banned File Paths (one per line):                           │
│  ┌────────────────────────────────────────────────────┐     │
│  │ (để trống)                                         │     │
│  └────────────────────────────────────────────────────┘     │
│                                                              │
│                              [ Apply Policy ]                │
└──────────────────────────────────────────────────────────────┘
```

**Điền chính xác:**
- **Policy Name:** `lab3-privesc-block`
- **Target Deployment:** `lab3-restricted`
- **Kernel Enforcers:** `AppArmor`
- **Built-in Defense Rules:** tick **Privilege Escalation Prevention**
- **Banned File Paths:** để trống

Nhấn **Apply Policy**.

**Bước 3.4 — Xem rules được sinh ra (CLI):**

```bash
kubectl get varmorpolicy lab3-privesc-block -n default \
  -o jsonpath='{.spec.policy.enhanceProtect.attackProtectionRules}' \
  | python3 -m json.tool
```

**Kết quả mong đợi:**
```json
[
  {
    "rules": [
      "disallow-abuse-user-ns",
      "disable-cap-privilege"
    ]
  }
]
```

**Giải thích từng rule:**
- `disallow-abuse-user-ns`: Chặn syscall `unshare(CLONE_NEWUSER)` và `clone(CLONE_NEWUSER)` — ngăn tạo user namespace mới
- `disable-cap-privilege`: Disable các Linux capability nguy hiểm như `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN` — ngăn process claim back các quyền nguy hiểm

**Bước 3.5 — Gắn label và restart pods:**

```bash
# Chờ agent load profile
sleep 15

# Gắn label
kubectl label deployment lab3-restricted sandbox.varmor.org/enable=true

# Restart pods
kubectl rollout restart deployment/lab3-restricted
kubectl rollout status deployment/lab3-restricted

# Lấy tên pod mới
POD3=$(kubectl get pods -l app=lab3-restricted -o jsonpath='{.items[0].metadata.name}')
echo "New pod: $POD3"

# Cài lại unshare trong pod mới
kubectl exec $POD3 -- apt-get install -y -qq util-linux 2>/dev/null
```

---

### Phần 4: Kiểm Tra Bảo Vệ

```bash
# Test 1: unshare --user -- PHẢI BỊ CHẶN
echo "=== Test 1: unshare --user --map-root-user id ==="
kubectl exec $POD3 -- unshare --user --map-root-user id 2>&1

echo ""
echo "=== Test 2: unshare --user shell ==="
kubectl exec $POD3 -- unshare --user --map-root-user sh -c 'echo "in namespace: $(id)"' 2>&1

echo ""
echo "=== Test 3: unshare kết hợp namespaces ==="
kubectl exec $POD3 -- unshare --user --map-root-user --pid --fork id 2>&1

echo ""
echo "=== Test 4: Thử clone với CLONE_NEWUSER flag ==="
kubectl exec $POD3 -- python3 -c "
import os, ctypes
CLONE_NEWUSER = 0x10000000
try:
    ctypes.CDLL('libc.so.6').unshare(CLONE_NEWUSER)
    print('unshare succeeded (BAD!)')
except Exception as e:
    print('unshare failed (GOOD):', e)
" 2>&1

echo ""
echo "=== Test 5: Các thao tác BÌNH THƯỜNG vẫn hoạt động ==="
kubectl exec $POD3 -- id
kubectl exec $POD3 -- ls /tmp/
kubectl exec $POD3 -- touch /tmp/testfile && echo "touch OK"
```

**Kết quả mong đợi — BẢO VỆ HOẠT ĐỘNG:**
```
=== Test 1: unshare --user --map-root-user id ===
unshare: unshare failed: Operation not permitted

=== Test 2: unshare --user shell ===
unshare: unshare failed: Operation not permitted

=== Test 3: unshare kết hợp namespaces ===
unshare: unshare failed: Operation not permitted

=== Test 4: Thử clone với CLONE_NEWUSER flag ===
unshare failed (GOOD): [Errno 1] Operation not permitted

=== Test 5: Các thao tác BÌNH THƯỜNG vẫn hoạt động ===
uid=0(root) gid=0(root) groups=0(root)
(empty)
touch OK
```

**Tại sao điều này hoạt động?** Rule `disallow-abuse-user-ns` trong vArmor được map tới AppArmor rule chặn syscall `unshare` với flag `CLONE_NEWUSER`. AppArmor intercept syscall này tại kernel level thông qua LSM hook `task_unshare`. Không có user-space trick nào có thể bypass vì check xảy ra trong kernel trước khi syscall được thực hiện.

---

### Phần 5: Dọn Dẹp

```bash
# Xóa policy (qua Console hoặc CLI)
kubectl delete varmorpolicy lab3-privesc-block -n default

# Xóa deployment
kubectl delete deployment lab3-restricted

# Verify
kubectl get varmorpolicy -n default | grep lab3
kubectl get deployment lab3-restricted 2>&1
```

---

### Câu Hỏi Tự Học

1. User namespace cho phép process "giả vờ" là root trong namespace riêng của mình. Tại sao đây là vấn đề bảo mật? Nghiên cứu về "CVE-2022-25636" và "CVE-2023-32233" — cả hai đều liên quan đến user namespace.

2. `disable-cap-privilege` tắt các capability nguy hiểm. Liệt kê 5 Linux capability nguy hiểm nhất và giải thích mỗi capability cho phép làm gì mà attacker muốn.

3. Sự khác nhau giữa `CAP_SYS_ADMIN` trong container (với user namespace) vs `CAP_SYS_ADMIN` trực tiếp trên host? Tại sao một số kernel path không phân biệt hai trường hợp này?

4. Nếu một ứng dụng cần `unshare` để hoạt động bình thường (ví dụ: buildah, podman in container), làm sao bạn cho phép user namespace cho process đó mà vẫn bảo vệ container?

---

## Lab 4: Bảo Vệ Ứng Dụng Đa Lớp

### Bối cảnh

Công ty bạn chuẩn bị deploy một web application lên production. Application này là mục tiêu có giá trị cao — nếu bị tấn công thành công, attacker có thể đọc database credentials (từ environment variables), thoát khỏi container, và leo thang quyền để kiểm soát cluster. Security team yêu cầu áp dụng **defense in depth**: nhiều lớp bảo vệ cùng lúc để đảm bảo ngay cả khi một lớp bị bypass, các lớp còn lại vẫn bảo vệ.

Bạn cần tạo một policy kết hợp tất cả: banned files + container escape prevention + privilege escalation prevention + hai enforcer (AppArmor và Seccomp).

### Mục tiêu

- Tạo policy tổng hợp với nhiều lớp bảo vệ đồng thời
- Kiểm tra nhiều vector tấn công đều bị chặn
- Hiểu tại sao kết hợp AppArmor + Seccomp mạnh hơn từng cái riêng lẻ
- Quan sát policy status trên Console khi áp dụng đa lớp

---

### Phần 1: Chuẩn Bị Môi Trường

```bash
ssh root@<server-address>

# Tạo deployment mô phỏng production web app
kubectl create deployment lab4-production --image=ubuntu:22.04 -- sleep infinity

# Chờ pod khởi động
kubectl rollout status deployment/lab4-production

# Lấy tên pod
POD4=$(kubectl get pods -l app=lab4-production -o jsonpath='{.items[0].metadata.name}')
echo "Pod: $POD4"

# Cài tools cần thiết để test
kubectl exec $POD4 -- apt-get update -qq 2>/dev/null
kubectl exec $POD4 -- apt-get install -y -qq util-linux 2>/dev/null
echo "Setup done"
```

---

### Phần 2: Tấn Công Không Có Bảo Vệ

Kiểm tra TẤT CẢ các vector tấn công đều hoạt động:

```bash
echo "=========================================="
echo "KIỂM TRA TẤN CÔNG KHI KHÔNG CÓ BẢO VỆ"
echo "=========================================="

# Vector 1: Đọc file nhạy cảm
echo ""
echo "--- Vector 1: Đọc /etc/shadow ---"
kubectl exec $POD4 -- cat /etc/shadow | head -3

# Vector 2: Đọc environment variables (có thể chứa DB passwords)
echo ""
echo "--- Vector 2: Đọc environment variables của PID 1 ---"
kubectl exec $POD4 -- cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -E "PASS|SECRET|KEY|TOKEN" || echo "(Không tìm thấy secrets — container sạch)"

# Vector 3: Container escape via core_pattern
echo ""
echo "--- Vector 3: Ghi core_pattern ---"
kubectl exec $POD4 -- sh -c 'echo "| /tmp/evil" > /proc/sys/kernel/core_pattern && echo "Ghi thành công (NGUY HIỂM!)"'
kubectl exec $POD4 -- sh -c 'echo "core" > /proc/sys/kernel/core_pattern'  # reset

# Vector 4: Privilege escalation via user namespace
echo ""
echo "--- Vector 4: unshare user namespace ---"
kubectl exec $POD4 -- unshare --user --map-root-user id 2>&1

echo ""
echo "Tất cả vector đều hoạt động khi KHÔNG có bảo vệ!"
```

---

### Phần 3: Áp Dụng Bảo Vệ Qua Console

**Bước 3.1 — Mở Console:** `http://<server-address>:30080`

**Bước 3.2 — Nhấn Load.**

**Bước 3.3 — Điền form Create Policy (đây là policy phức tạp nhất):**

```
┌──────────────────────────────────────────────────────────────┐
│  Create VarmorPolicy                                         │
│                                                              │
│  Policy Name *               Target Deployment *             │
│  ┌─────────────────────┐    ┌──────────────────────────┐    │
│  │ lab4-full-hardening │    │ ▼ lab4-production        │    │
│  └─────────────────────┘    └──────────────────────────┘    │
│                                                              │
│  Kernel Enforcers:                                           │
│  [✓] AppArmor   [✓] Seccomp   [ ] BPF                       │
│  ↑ Tick CẢ HAI AppArmor VÀ Seccomp                          │
│                                                              │
│  Built-in Defense Rules:                                     │
│  [✓] Container Escape Prevention    ← TICK                  │
│  [✓] Privilege Escalation Prevention ← TICK LUÔN CẢ HAI     │
│                                                              │
│  Banned File Paths (one per line):                           │
│  ┌────────────────────────────────────────────────────┐     │
│  │ /etc/shadow                                        │     │
│  │ /etc/passwd                                        │     │
│  │ /proc/sys/kernel/core_pattern                      │     │
│  │ /proc/sysrq-trigger                                │     │
│  │ /proc/keys                                         │     │
│  └────────────────────────────────────────────────────┘     │
│                                                              │
│                              [ Apply Policy ]                │
└──────────────────────────────────────────────────────────────┘
```

**Điền chính xác:**
- **Policy Name:** `lab4-full-hardening`
- **Target Deployment:** `lab4-production`
- **Kernel Enforcers:** tick **cả AppArmor VÀ Seccomp**
- **Built-in Defense Rules:** tick **cả hai** Container Escape Prevention VÀ Privilege Escalation Prevention
- **Banned File Paths:** `/etc/shadow`, `/etc/passwd`, `/proc/sys/kernel/core_pattern`, `/proc/sysrq-trigger`, `/proc/keys`

Nhấn **Apply Policy**.

**Bước 3.4 — Kiểm tra policy trên Console:**

Trong bảng **Active Policies**, tìm `lab4-full-hardening`. Chú ý cột **Mode** hiển thị `EnhanceProt` và cột **Status** — ban đầu là `Pending`, sau ~15s đổi sang `Ready`.

**Bước 3.5 — Xem toàn bộ policy được tạo (CLI):**

```bash
# Chờ agent load
sleep 15

# Xem toàn bộ spec
kubectl get varmorpolicy lab4-full-hardening -n default -o yaml

# Xem enforcer được set
kubectl get varmorpolicy lab4-full-hardening -n default \
  -o jsonpath='{.spec.policy.enforcer}'

# Xem tất cả rules
echo ""
echo "--- Attack Protection Rules ---"
kubectl get varmorpolicy lab4-full-hardening -n default \
  -o jsonpath='{.spec.policy.enhanceProtect.attackProtectionRules}' \
  | python3 -m json.tool

echo ""
echo "--- AppArmor Raw Rules (Banned Files) ---"
kubectl get varmorpolicy lab4-full-hardening -n default \
  -o jsonpath='{.spec.policy.enhanceProtect.appArmorRawRules}' \
  | python3 -m json.tool
```

**Kết quả mong đợi:**
```
AppArmor|Seccomp

--- Attack Protection Rules ---
[
  {
    "rules": [
      "disallow-write-core-pattern",
      "disallow-mount-securityfs",
      "disallow-write-release-agent",
      "disallow-abuse-user-ns",
      "disable-cap-privilege"
    ]
  }
]

--- AppArmor Raw Rules ---
[
  {"rules": "deny /etc/shadow rwmlk,"},
  {"rules": "deny /etc/passwd rwmlk,"},
  {"rules": "deny /proc/sys/kernel/core_pattern rwmlk,"},
  {"rules": "deny /proc/sysrq-trigger rwmlk,"},
  {"rules": "deny /proc/keys rwmlk,"}
]
```

**Bước 3.6 — Gắn label và restart:**

```bash
# Gắn label
kubectl label deployment lab4-production sandbox.varmor.org/enable=true

# Restart
kubectl rollout restart deployment/lab4-production
kubectl rollout status deployment/lab4-production

# Lấy pod mới
POD4=$(kubectl get pods -l app=lab4-production -o jsonpath='{.items[0].metadata.name}')
echo "New pod: $POD4"

# Cài lại tools
kubectl exec $POD4 -- apt-get install -y -qq util-linux 2>/dev/null
```

---

### Phần 4: Kiểm Tra Bảo Vệ

Chạy lại đúng các vector tấn công từ Phần 2:

```bash
echo "=========================================="
echo "KIỂM TRA SAU KHI ÁP DỤNG BẢO VỆ ĐA LỚP"
echo "=========================================="

BLOCKED=0
TOTAL=4

# Vector 1: Đọc file nhạy cảm
echo ""
echo "--- Vector 1: Đọc /etc/shadow ---"
RESULT=$(kubectl exec $POD4 -- cat /etc/shadow 2>&1)
if echo "$RESULT" | grep -q "Permission denied"; then
  echo "BLOCKED: $RESULT"
  BLOCKED=$((BLOCKED+1))
else
  echo "WARNING - Không bị chặn: $RESULT"
fi

# Vector 2: Ghi core_pattern
echo ""
echo "--- Vector 2: Ghi core_pattern ---"
RESULT=$(kubectl exec $POD4 -- sh -c 'echo "| /tmp/evil" > /proc/sys/kernel/core_pattern 2>&1')
if echo "$RESULT" | grep -q "Permission denied"; then
  echo "BLOCKED: $RESULT"
  BLOCKED=$((BLOCKED+1))
else
  # Nếu không có output lỗi, kiểm tra xem có thực sự thay đổi không
  PATTERN=$(kubectl exec $POD4 -- cat /proc/sys/kernel/core_pattern)
  if [ "$PATTERN" = "core" ]; then
    echo "BLOCKED (core_pattern không đổi: $PATTERN)"
    BLOCKED=$((BLOCKED+1))
  else
    echo "WARNING - core_pattern bị thay đổi thành: $PATTERN"
    kubectl exec $POD4 -- sh -c 'echo "core" > /proc/sys/kernel/core_pattern'
  fi
fi

# Vector 3: unshare user namespace
echo ""
echo "--- Vector 3: unshare --user --map-root-user ---"
RESULT=$(kubectl exec $POD4 -- unshare --user --map-root-user id 2>&1)
if echo "$RESULT" | grep -qE "Operation not permitted|Permission denied"; then
  echo "BLOCKED: $RESULT"
  BLOCKED=$((BLOCKED+1))
else
  echo "WARNING - Không bị chặn: $RESULT"
fi

# Vector 4: Đọc /proc/keys
echo ""
echo "--- Vector 4: Đọc /proc/keys ---"
RESULT=$(kubectl exec $POD4 -- cat /proc/keys 2>&1)
if echo "$RESULT" | grep -q "Permission denied"; then
  echo "BLOCKED: $RESULT"
  BLOCKED=$((BLOCKED+1))
else
  echo "WARNING - Không bị chặn: $RESULT"
fi

# Tổng kết
echo ""
echo "=========================================="
echo "KẾT QUẢ: $BLOCKED/$TOTAL vector bị chặn"
if [ "$BLOCKED" -eq "$TOTAL" ]; then
  echo "HOÀN HẢO — Tất cả vector đều bị chặn!"
else
  echo "LƯU Ý — Một số vector không bị chặn (agent có thể chưa ready)"
fi
echo "=========================================="

# Kiểm tra thao tác bình thường vẫn hoạt động
echo ""
echo "--- Thao tác BÌNH THƯỜNG vẫn hoạt động ---"
kubectl exec $POD4 -- id
kubectl exec $POD4 -- ls /tmp/
kubectl exec $POD4 -- touch /tmp/workfile && cat /tmp/workfile || echo "(OK - file empty)"
kubectl exec $POD4 -- cat /etc/hostname
```

**Kết quả mong đợi:**
```
==========================================
KIỂM TRA SAU KHI ÁP DỤNG BẢO VỆ ĐA LỚP
==========================================

--- Vector 1: Đọc /etc/shadow ---
BLOCKED: cat: /etc/shadow: Permission denied

--- Vector 2: Ghi core_pattern ---
BLOCKED: sh: echo: write error: Permission denied

--- Vector 3: unshare --user --map-root-user ---
BLOCKED: unshare: unshare failed: Operation not permitted

--- Vector 4: Đọc /proc/keys ---
BLOCKED: cat: /proc/keys: Permission denied

==========================================
KẾT QUẢ: 4/4 vector bị chặn
HOÀN HẢO — Tất cả vector đều bị chặn!
==========================================

--- Thao tác BÌNH THƯỜNG vẫn hoạt động ---
uid=0(root) gid=0(root) groups=0(root)
(empty or workfile)
lab4-production-8a9b0c1d2-e5fgh
```

**Tại sao AppArmor + Seccomp mạnh hơn từng cái đơn lẻ?** AppArmor kiểm soát truy cập theo **path** (file, network, capability) dựa trên profile. Seccomp kiểm soát ở **syscall level** — có thể block/allow từng syscall cụ thể bất kể path. Kết hợp hai lớp: ngay cả khi attacker tìm được path thay thế (ví dụ: dùng syscall `openat` thay vì `open`), Seccomp vẫn có thể block. Defense in depth.

---

### Phần 5: Dọn Dẹp

```bash
# Xóa policy (qua Console hoặc CLI)
kubectl delete varmorpolicy lab4-full-hardening -n default

# Xóa deployment
kubectl delete deployment lab4-production

# Verify
kubectl get varmorpolicy -n default | grep lab4
kubectl get deployment lab4-production 2>&1
```

---

### Câu Hỏi Tự Học

1. Policy này dùng `AppArmor|Seccomp` (hai enforcer). Khi có xung đột (AppArmor allow nhưng Seccomp deny), kết quả là gì? Enforcer nào có quyền ưu tiên?

2. Banned Files trong policy này bao gồm cả `/proc/sys/kernel/core_pattern` — nhưng Lab 2 cũng chặn điều này qua `container_escape` rule. Nếu cả hai rule cùng apply, có conflict không? AppArmor xử lý thế nào khi có nhiều deny rule cho cùng một path?

3. Trong production, "defense in depth" thường có thêm lớp thứ ba: **network policy** (chặn container giao tiếp với service không cần thiết). Bạn có thể thêm NetworkProxy enforcer vào policy này không? Điều gì xảy ra?

4. Policy này không protect thư mục `/var/run/docker.sock` hay `/run/containerd/containerd.sock`. Nếu container có thể access những socket này, điều gì xảy ra?

---

## Lab 5: Quản Lý Và Kiểm Soát Chính Sách

### Bối cảnh

Sự cố bảo mật xảy ra lúc 2 giờ sáng: một container production đang bị tấn công. Security team cần **nhanh chóng** áp dụng emergency policy để ngăn attacker leo thang, sau đó **kiểm tra audit trail** để biết ai đã làm gì, policy nào đang active, và ghi lại evidence cho incident report. Sau khi sự cố được xử lý, cần gỡ bỏ emergency policy và xác nhận mọi thứ trở về trạng thái bình thường.

Lab này tập trung vào **policy lifecycle management** và **audit trail** — kỹ năng quan trọng cho Security Operations.

### Mục tiêu

- Thực hành tạo và xóa policy nhanh trong tình huống khẩn cấp
- Đọc và phân tích audit log để hiểu ai làm gì, khi nào
- Sử dụng Console như công cụ incident response
- Hiểu tầm quan trọng của audit trail trong forensics

---

### Phần 1: Chuẩn Bị Môi Trường

```bash
ssh root@<server-address>

# Mở terminal thứ hai để theo dõi audit logs real-time
# Terminal 1: theo dõi logs
CONSOLE_POD=$(kubectl get pods -l app=armor-pilot -o jsonpath='{.items[0].metadata.name}')
echo "Console pod: $CONSOLE_POD"

# Bắt đầu follow audit log (giữ terminal này mở)
kubectl logs -f $CONSOLE_POD | grep '\[AUDIT\]'
```

**Mở terminal SSH thứ hai:**

```bash
ssh root@<server-address>
# Terminal 2 — để chạy các lệnh setup và verify

# Tạo deployment mô phỏng service đang bị tấn công
kubectl create deployment lab5-incident --image=ubuntu:22.04 -- sleep infinity
kubectl rollout status deployment/lab5-incident

POD5=$(kubectl get pods -l app=lab5-incident -o jsonpath='{.items[0].metadata.name}')
echo "Incident pod: $POD5"
```

---

### Phần 2: Mô Phỏng Tấn Công Đang Diễn Ra

```bash
# Trong Terminal 2 — mô phỏng attacker đang hoạt động
echo "=== INCIDENT: Container đang bị tấn công ==="

# Attacker đọc thông tin hệ thống
kubectl exec $POD5 -- cat /etc/shadow | head -2

# Attacker đang cố ghi core_pattern
kubectl exec $POD5 -- sh -c 'echo "| /tmp/evil" > /proc/sys/kernel/core_pattern 2>&1'
echo "core_pattern: $(kubectl exec $POD5 -- cat /proc/sys/kernel/core_pattern)"

# Reset
kubectl exec $POD5 -- sh -c 'echo "core" > /proc/sys/kernel/core_pattern'

echo ""
echo "INCIDENT ACTIVE: Cần áp dụng emergency policy ngay lập tức!"
```

---

### Phần 3: Phản Ứng Khẩn Cấp Qua Console

**Mục tiêu: Áp dụng emergency policy trong thời gian nhanh nhất có thể.**

**Bước 3.1 — Mở Console ngay lập tức:**
```
http://<server-address>:30080
Đăng nhập: admin / <configured-admin-password>
```

**Bước 3.2 — Nhấn Load để tải danh sách.**

**Bước 3.3 — Điền form NHANH (đây là tình huống khẩn cấp):**

```
┌──────────────────────────────────────────────────────────────┐
│  Create VarmorPolicy                                         │
│                                                              │
│  Policy Name *               Target Deployment *             │
│  ┌─────────────────────┐    ┌──────────────────────────┐    │
│  │ emergency-lockdown  │    │ ▼ lab5-incident          │    │
│  └─────────────────────┘    └──────────────────────────┘    │
│                                                              │
│  Kernel Enforcers:                                           │
│  [✓] AppArmor   [ ] Seccomp   [ ] BPF                       │
│                                                              │
│  Built-in Defense Rules:                                     │
│  [✓] Container Escape Prevention    ← TICK                  │
│  [✓] Privilege Escalation Prevention ← TICK                  │
│                                                              │
│  Banned File Paths (one per line):                           │
│  ┌────────────────────────────────────────────────────┐     │
│  │ /etc/shadow                                        │     │
│  │ /proc/sys/kernel/core_pattern                      │     │
│  └────────────────────────────────────────────────────┘     │
│                                                              │
│                              [ Apply Policy ]                │
└──────────────────────────────────────────────────────────────┘
```

**Điền:**
- **Policy Name:** `emergency-lockdown`
- **Target Deployment:** `lab5-incident`
- **Enforcers:** `AppArmor`
- **Rules:** Tick **cả hai** rules
- **Banned Files:** `/etc/shadow`, `/proc/sys/kernel/core_pattern`

Nhấn **Apply Policy** → ghi lại thời điểm (timestamp).

**Bước 3.4 — Trong Terminal 2: gắn label và restart nhanh:**

```bash
# Ghi lại thời điểm bắt đầu response
INCIDENT_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "Incident response started at: $INCIDENT_START"

# Chờ agent load profile
sleep 15

# Apply protection
kubectl label deployment lab5-incident sandbox.varmor.org/enable=true
kubectl rollout restart deployment/lab5-incident
kubectl rollout status deployment/lab5-incident

POD5=$(kubectl get pods -l app=lab5-incident -o jsonpath='{.items[0].metadata.name}')
echo "Incident contained at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Protected pod: $POD5"
```

---

### Phần 4: Kiểm Tra và Phân Tích Audit Trail

**Bước 4.1 — Xác nhận bảo vệ hoạt động:**

```bash
# Verify attacker bị chặn
echo "=== Verify emergency policy active ==="
kubectl exec $POD5 -- cat /etc/shadow 2>&1
kubectl exec $POD5 -- sh -c 'echo "| /tmp/evil" > /proc/sys/kernel/core_pattern 2>&1'
kubectl exec $POD5 -- unshare --user --map-root-user id 2>&1
```

**Bước 4.2 — Đọc audit trail từ Console logs:**

```bash
# Lấy toàn bộ audit log
echo "=== AUDIT TRAIL ==="
kubectl logs $CONSOLE_POD | grep '\[AUDIT\]'

# Lọc chỉ xem actions liên quan đến lab5
echo ""
echo "=== Actions liên quan đến emergency-lockdown ==="
kubectl logs $CONSOLE_POD | grep '\[AUDIT\]' | grep 'emergency-lockdown'

# Tìm thời điểm CREATE policy
echo ""
echo "=== Thời điểm emergency policy được tạo ==="
kubectl logs $CONSOLE_POD | grep '\[AUDIT\]' | grep 'action=CREATE' | grep 'emergency-lockdown'

# Xem toàn bộ history của user admin
echo ""
echo "=== Timeline hoạt động của admin ==="
kubectl logs $CONSOLE_POD | grep '\[AUDIT\]' | grep 'user=admin' | tail -20

# Đếm số policies đã tạo và xóa
echo ""
echo "=== Thống kê ==="
echo -n "Tổng số CREATE: "
kubectl logs $CONSOLE_POD | grep '\[AUDIT\]' | grep 'action=CREATE' | wc -l
echo -n "Tổng số DELETE: "
kubectl logs $CONSOLE_POD | grep '\[AUDIT\]' | grep 'action=DELETE' | wc -l
echo -n "Tổng số FAILURE: "
kubectl logs $CONSOLE_POD | grep '\[AUDIT\]' | grep 'status=FAILURE' | wc -l
```

**Kết quả mong đợi của audit trail:**
```
=== AUDIT TRAIL ===
[2026-05-15T02:14:33Z] [AUDIT] user=admin action=CREATE policy=emergency-lockdown namespace=default status=SUCCESS
[2026-05-15T02:14:33Z] [AUDIT] user=admin action=CREATE policy=lab1-sensitive-files namespace=default status=SUCCESS
[2026-05-15T02:14:33Z] [AUDIT] user=admin action=DELETE policy=lab1-sensitive-files namespace=default status=SUCCESS
...

=== Actions liên quan đến emergency-lockdown ===
[2026-05-15T02:14:33Z] [AUDIT] user=admin action=CREATE policy=emergency-lockdown namespace=default status=SUCCESS

=== Timeline hoạt động của admin ===
[2026-05-15T02:01:15Z] [AUDIT] user=admin action=CREATE policy=lab1-sensitive-files namespace=default status=SUCCESS
[2026-05-15T02:08:42Z] [AUDIT] user=admin action=DELETE policy=lab1-sensitive-files namespace=default status=SUCCESS
[2026-05-15T02:14:33Z] [AUDIT] user=admin action=CREATE policy=emergency-lockdown namespace=default status=SUCCESS
```

**Bước 4.3 — Đọc audit log từ file (docker level — nơi Fluentd thu thập):**

```bash
# Tìm log file của console pod trong node
docker exec varmor-lab-control-plane \
  ls /var/log/containers/ | grep armor-pilot

# Xem log từ node level (đây là nguồn Fluentd/Filebeat đọc)
LOG_FILE=$(docker exec varmor-lab-control-plane \
  ls /var/log/containers/ | grep armor-pilot | head -1)

echo "Log file: $LOG_FILE"

docker exec varmor-lab-control-plane \
  cat /var/log/containers/$LOG_FILE | grep AUDIT | tail -10
```

**Bước 4.4 — Kiểm tra policy hiện tại trên Console:**

Trên trình duyệt, nhìn bảng **Active Policies**. Xác nhận:
- `emergency-lockdown` hiển thị với status **Ready**
- Badge trên sidebar cho `lab5-incident` đổi sang **Protected**

```bash
# Xác minh qua API
export ARMORPILOT_PASSWORD='<configured-admin-password>'
curl -s -u "admin:${ARMORPILOT_PASSWORD}" \
  http://<server-address>:30080/api/namespaces/default/policies \
  | python3 -m json.tool | grep -A8 '"name": "emergency-lockdown"'
```

**Bước 4.5 — Thử tạo policy trùng tên để xem FAILURE log:**

Trên Console, thử tạo lại policy với đúng tên `emergency-lockdown` → Console báo lỗi.

```bash
# Quan sát Terminal 1 (logs) — sẽ xuất hiện FAILURE log
# [2026-05-15T02:20:11Z] [AUDIT] user=admin action=CREATE policy=emergency-lockdown namespace=default status=FAILURE details="Conflict"
```

---

### Phần 5: Dọn Dẹp — Kết Thúc Incident

Sau khi sự cố được xử lý, gỡ bỏ emergency policy (trong thực tế sẽ thay bằng policy long-term):

```bash
# Ghi lại thời điểm đóng incident
echo "Incident closed at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Xóa emergency policy qua Console:
# 1. Mở Console
# 2. Tìm "emergency-lockdown" trong bảng Active Policies
# 3. Nhấn Delete → xác nhận

# Hoặc xóa bằng CLI:
kubectl delete varmorpolicy emergency-lockdown -n default

# Xác nhận trong audit log
echo ""
echo "=== Audit log sau khi xóa ==="
kubectl logs $CONSOLE_POD | grep '\[AUDIT\]' | grep 'emergency-lockdown'

# Xóa deployment
kubectl delete deployment lab5-incident

# Verify sạch
kubectl get varmorpolicy -n default | grep lab5
kubectl get deployment lab5-incident 2>&1
```

**Kết quả mong đợi — audit log đầy đủ:**
```
[2026-05-15T02:14:33Z] [AUDIT] user=admin action=CREATE policy=emergency-lockdown namespace=default status=SUCCESS
[2026-05-15T02:20:11Z] [AUDIT] user=admin action=CREATE policy=emergency-lockdown namespace=default status=FAILURE details="Conflict"
[2026-05-15T02:25:47Z] [AUDIT] user=admin action=DELETE policy=emergency-lockdown namespace=default status=SUCCESS
```

**Ý nghĩa của audit trail này:** Trong incident response, audit log trả lời câu hỏi "WHEN was protection applied?" (02:14:33Z) và "WHEN was it removed?" (02:25:47Z). Khoảng thời gian giữa hai event này là **thời gian container được bảo vệ**. Nếu có FAILURE log lúc 02:20:11Z, điều tra xem ai đã cố tạo lại policy trùng tên — có thể là lỗi hoặc dấu hiệu bất thường.

---

### Câu Hỏi Tự Học

1. Audit log hiện tại lưu trong pod STDOUT. Nếu pod bị restart (do OOMKilled, crash...), log trước đó **mất hết**. Bạn cần làm gì để đảm bảo audit log được lưu lâu dài cho incident response và compliance?

2. Audit log hiện tại chỉ ghi `user=admin` — chỉ có một user. Trong môi trường production với nhiều người, bạn cần mở rộng hệ thống như thế nào để biết chính xác ai (tên cụ thể, IP nguồn) đã tạo/xóa policy?

3. Khoảng thời gian từ khi phát hiện incident đến khi apply policy (Mean Time to Protect) trong lab này là bao lâu? Trong thực tế, có thể tự động hóa bước này không? Nếu có, dùng công cụ nào?

4. Nếu attacker đã vào được Console (đánh cắp được credential admin), họ có thể **xóa policy** để gỡ bảo vệ khỏi container. Bạn cần thêm cơ chế bảo vệ nào để ngăn điều này?

---

## Bảng Tổng Hợp Các Lab

| Lab | Tiêu đề | Vector Tấn Công | Cơ Chế Bảo Vệ | Rule/Config | Kernel Mechanism |
|-----|---------|-----------------|---------------|-------------|-----------------|
| 1 | Ngăn đánh cắp thông tin nhạy cảm | Đọc `/etc/shadow`, `/etc/passwd`, kernel keys | Banned File Paths | `deny /path rwmlk,` | AppArmor `file_permission` LSM hook |
| 2 | Ngăn Container Escape | Ghi `/proc/sys/kernel/core_pattern` (CVE-2022-0492) | `container_escape` rule | `disallow-write-core-pattern`, `disallow-write-release-agent` | AppArmor `file_permission` + procfs |
| 3 | Chống leo thang đặc quyền | `unshare --user --map-root-user` | `privilege_escalation` rule | `disallow-abuse-user-ns`, `disable-cap-privilege` | AppArmor `task_unshare` LSM hook |
| 4 | Bảo vệ đa lớp | Tất cả vector kết hợp | AppArmor + Seccomp + tất cả rules | Kết hợp tất cả | AppArmor + Seccomp syscall filter |
| 5 | Quản lý policy lifecycle | Incident response | Policy lifecycle + Audit trail | Tất cả rules | Audit logging + forensics |

---

## Phụ Lục: Tham Chiếu Nhanh

### Các lệnh kubectl dùng thường xuyên trong labs

```bash
# Tạo deployment nhanh
kubectl create deployment <name> --image=ubuntu:22.04 -- sleep infinity

# Chờ pod ready
kubectl rollout status deployment/<name>

# Lấy tên pod
kubectl get pods -l app=<name> -o jsonpath='{.items[0].metadata.name}'

# Exec vào pod
kubectl exec <pod> -- <command>

# Gắn label vArmor
kubectl label deployment <name> sandbox.varmor.org/enable=true

# Restart deployment
kubectl rollout restart deployment/<name>

# Xem varmorpolicy
kubectl get varmorpolicies -n default
kubectl get varmorpolicy <name> -n default -o yaml

# Xem audit logs
CONSOLE_POD=$(kubectl get pods -l app=armor-pilot -o jsonpath='{.items[0].metadata.name}')
kubectl logs $CONSOLE_POD | grep '\[AUDIT\]'

# Dọn dẹp
kubectl delete varmorpolicy <name> -n default
kubectl delete deployment <name>
```

### Format Audit Log

```
[YYYY-MM-DDTHH:MM:SSZ] [AUDIT] user=<username> action=<CREATE|DELETE> policy=<name> namespace=<ns> status=<SUCCESS|FAILURE> [details="<msg>"]
```

### Quy Trình Áp Dụng Policy Đúng Cách

```
1. Tạo deployment (chưa có label)
2. Tạo policy trên Console → chờ Status = Ready (~15s)
3. kubectl label deployment <name> sandbox.varmor.org/enable=true
4. kubectl rollout restart deployment/<name>
5. Lấy tên pod mới: POD=$(kubectl get pods -l app=<name> -o jsonpath='{.items[0].metadata.name}')
6. Kiểm tra annotation: kubectl get pod $POD -o jsonpath='{.metadata.annotations}'
7. Test các vector tấn công đều bị chặn
```

### Profile Name Format

```
varmor-<namespace>-<policyname>
Ví dụ: varmor-default-lab1-sensitive-files
```

---

*Labs được thiết kế theo nguyên tắc: tấn công trước khi phòng thủ — để hiểu TẠI SAO bảo vệ cần thiết, không chỉ HOW TO áp dụng nó.*
