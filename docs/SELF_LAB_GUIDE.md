# Hướng Dẫn Tự Lab: vArmor Console Security
## Học Bảo Mật Container Bằng Thực Hành — Có Giải Thích Từng Bước

> **Server lab:** `172.30.2.129` | **Console:** `http://172.30.2.129:8080`  
> **Tài khoản:** `admin / Admin@vArmor2026!`  
> **Mức độ:** Beginner → Intermediate | **Thời gian ước tính:** 4-6 giờ

---

## Mục Lục

- [Phần 0 — Nền tảng: Hiểu vArmor Là Gì](#phần-0--nền-tảng-hiểu-varmor-là-gì)
- [Phần 1 — Chuẩn Bị Môi Trường](#phần-1--chuẩn-bị-môi-trường)
- [Lab 01 — Xác Thực & Bảo Mật API](#lab-01--xác-thực--bảo-mật-api)
- [Lab 02 — Khám Phá Deployment](#lab-02--khám-phá-deployment)
- [Lab 03 — Vòng Đời Policy (CRUD)](#lab-03--vòng-đời-policy-crud)
- [Lab 04 — Chặn File Nhạy Cảm](#lab-04--chặn-file-nhạy-cảm)
- [Lab 05 — Ngăn Container Escape](#lab-05--ngăn-container-escape)
- [Lab 06 — Audit Log](#lab-06--audit-log)
- [Lab 07 — RBAC & Phân Quyền](#lab-07--rbac--phân-quyền)
- [Phần Tổng Kết](#phần-tổng-kết)

---

## Phần 0 — Nền Tảng: Hiểu vArmor Là Gì

### 0.1 Vấn đề cần giải quyết

Khi bạn chạy một container trong Kubernetes, mặc định container đó có thể:
- Đọc `/etc/shadow` (file password của host nếu không được cô lập tốt)
- Ghi vào `/proc/sys/kernel/core_pattern` để thực hiện container breakout
- Mount filesystem hệ thống
- Leo thang đặc quyền lên root

**Container isolation ≠ security isolation.** Namespace và cgroup chỉ cô lập tài nguyên, không chặn system call nguy hiểm.

### 0.2 Giải pháp: Linux Security Module (LSM)

```
Application
    │
    ▼
System Call Interface (kernel)
    │
    ▼  ◄── LSM hooks chặn ở đây
Kernel Operations
    │
    ▼
Hardware
```

**AppArmor** và **Seccomp** là 2 LSM phổ biến:
- **AppArmor** = kiểm soát truy cập file, mạng, capability dựa trên *profile*
- **Seccomp** = lọc system call (syscall filtering)
- **eBPF** = lập trình kernel trực tiếp, linh hoạt nhất

### 0.3 Tại sao chọn vArmor thay vì tự viết AppArmor profile?

| Cách tiếp cận | Ưu điểm | Nhược điểm |
|---|---|---|
| Tự viết AppArmor profile | Kiểm soát tuyệt đối | Phức tạp, dễ sai, không phải K8s-native |
| Pod Security Policy (đã deprecated) | Tích hợp K8s | Bị xóa từ K8s 1.25 |
| vArmor | CRD-native, built-in rules, UI | Cần cài thêm |

vArmor cung cấp **built-in attack protection rules** — bộ luật đã được nghiên cứu cho các CVE phổ biến, bạn chỉ cần khai báo tên rule là xong.

### 0.4 Kiến trúc vArmor

```
┌──────────────────────────────────────────────────────┐
│                   Kubernetes Cluster                  │
│                                                      │
│  ┌─────────────┐   CRD    ┌──────────────────────┐  │
│  │   Console   │ ──────►  │  VarmorPolicy (CRD)  │  │
│  │  (Web GUI)  │          │  varmor.org/v1beta1  │  │
│  └─────────────┘          └──────────┬───────────┘  │
│                                      │               │
│                              Watch & Sync            │
│                                      │               │
│                            ┌─────────▼──────────┐    │
│                            │  varmor-manager    │    │
│                            │  (control plane)   │    │
│                            └─────────┬──────────┘    │
│                                      │               │
│                          Distribute profiles         │
│                                      │               │
│    ┌──────────┐  ┌──────────┐ ┌──────▼───────┐       │
│    │  Node 1  │  │  Node 2  │ │   varmor-    │       │
│    │  (Pods)  │  │  (Pods)  │ │   agent      │       │
│    │  AppArmor│  │  AppArmor│ │ (DaemonSet)  │       │
│    └──────────┘  └──────────┘ └──────────────┘       │
└──────────────────────────────────────────────────────┘
```

---

## Phần 1 — Chuẩn Bị Môi Trường

### Bước 1.1: SSH vào server

```bash
ssh root@172.30.2.129
# Password: abc@123
```

**Tại sao SSH?** Console chạy trong Kubernetes cluster trên máy này. Ta cần truy cập trực tiếp để chạy `kubectl` và xem log nội bộ.

### Bước 1.2: Kiểm tra cluster đang chạy

```bash
kubectl cluster-info
```

**Kết quả mong đợi:**
```
Kubernetes control plane is running at https://127.0.0.1:XXXXX
```

**Giải thích:** Cluster này là **Kind (Kubernetes in Docker)** — chạy toàn bộ K8s node trong Docker container. Phù hợp cho lab vì không cần máy ảo riêng.

```bash
kubectl get nodes
```

Bạn sẽ thấy 1 node `varmor-lab-control-plane` với status `Ready`.

### Bước 1.3: Xem các thành phần đang chạy

```bash
kubectl get pods -A
```

**Giải thích các namespace quan trọng:**

| Namespace | Chứa gì |
|---|---|
| `kube-system` | Core K8s (etcd, API server, scheduler...) |
| `varmor` | vArmor manager + agent DaemonSet |
| `default` | Console của chúng ta + workload thực |

```bash
# Xem chi tiết vArmor
kubectl get pods -n varmor
```

```bash
# Xem Console
kubectl get pods -l app=varmor-console
```

### Bước 1.4: Kiểm tra Console hoạt động

```bash
curl -s http://127.0.0.1:8080/ | head -5
```

Console đang được expose qua `kubectl port-forward` — một dịch vụ systemd giữ tunnel này luôn mở:

```bash
systemctl status varmor-console-pf
```

**Tại sao dùng port-forward thay vì NodePort trực tiếp?** Kind cluster không map NodePort ra host machine mặc định. Port-forward là cách đơn giản nhất cho môi trường lab.

### Bước 1.5: Xem CRD của vArmor đã được cài

```bash
kubectl get crd | grep varmor
```

**Kết quả:**
```
varmorclusterpolicies.crd.varmor.org   ...
varmorpolicies.crd.varmor.org          ...
```

**Giải thích:** CRD (Custom Resource Definition) mở rộng Kubernetes API. `VarmorPolicy` là loại resource tùy chỉnh — khi bạn tạo một VarmorPolicy, K8s API nhận và vArmor manager xử lý nó.

**Ghi nhớ:** API group là `crd.varmor.org`, không phải `varmor.org`. Đây là điểm dễ nhầm vì documentation cũ dùng `varmor.org`.

---

## Lab 01 — Xác Thực & Bảo Mật API

### Mục tiêu học tập
Hiểu cơ chế **HTTP Basic Authentication**, tại sao cần bảo vệ API, và cách kiểm tra đúng cách.

### Lý thuyết trước khi làm

**HTTP Basic Auth hoạt động thế nào?**

```
Client                          Server
  │                               │
  ├── GET /api/policies ─────────►│
  │                               ├── "Cần auth?"
  │◄── 401 WWW-Authenticate ──────┤
  │                               │
  ├── GET /api/policies ─────────►│
  │   Authorization: Basic base64(user:pass)
  │                               ├── Giải mã + kiểm tra
  │◄── 200 OK ────────────────────┤
```

**Tại sao dùng Basic Auth trong lab này?**
- Đơn giản, dễ hiểu, không cần thư viện
- Đủ bảo mật khi kết hợp với HTTPS (trong prod)
- Phù hợp cho lab để học concept trước khi học OAuth2/JWT

**Tại sao credential lưu trong K8s Secret, không hardcode?**
```bash
kubectl get secret varmor-console-secret -o yaml
```
Bạn sẽ thấy `data.ADMIN_USER` và `data.ADMIN_PASS` được **base64 encode** (không encrypt). Lý do chính không phải để encrypt mà để:
1. Tách config khỏi code (12-factor app)
2. Dễ thay đổi password mà không cần rebuild image
3. RBAC của K8s kiểm soát ai được đọc Secret

---

### Thực hành Lab 01

**Bước 1: Thử truy cập không có auth**

```bash
curl -v http://127.0.0.1:8080/api/namespaces/default/policies
```

**Phân tích output:**
```
< HTTP/1.1 401 Unauthorized
< WWW-Authenticate: Basic realm="vArmor Console"
< Content-Type: application/json
```

- `401 Unauthorized`: Server hiểu request nhưng từ chối vì chưa có danh tính
- `WWW-Authenticate`: Header thông báo phương thức auth yêu cầu (Basic)
- `realm="vArmor Console"`: Tên "realm" — browser sẽ hiển thị cái này trong popup login

**Bước 2: Tạo Basic Auth header thủ công để hiểu bên trong**

```bash
# Encode user:pass thành base64
echo -n "admin:Admin@vArmor2026!" | base64
```

Output sẽ là: `YWRtaW46QWRtaW5AdkFybW9yMjAyNiE=`

```bash
# Dùng header thủ công
curl -H "Authorization: Basic YWRtaW46QWRtaW5AdkFybW9yMjAyNiE=" \
     http://127.0.0.1:8080/api/namespaces/default/policies
```

**Tại sao `echo -n`?** Thiếu `-n` sẽ có thêm ký tự newline vào chuỗi, làm sai base64.

**Bước 3: Dùng flag -u của curl (cách thực tế)**

```bash
curl -u "admin:Admin@vArmor2026!" \
     http://127.0.0.1:8080/api/namespaces/default/policies
```

curl tự encode thành Basic Auth header. **Giải thích:** `-u user:pass` là shorthand, curl sẽ tự tính `base64(user:pass)` và thêm header.

**Bước 4: Thử password sai để xem phản hồi**

```bash
curl -v -u "admin:wrongpassword" \
     http://127.0.0.1:8080/api/namespaces/default/policies
```

Server trả `401` không có thêm thông tin. **Tại sao không nói "password sai" hay "user không tồn tại"?** Đây là bảo mật — nếu nói rõ, attacker biết được username có tồn tại không (user enumeration attack).

**Bước 5: Kiểm tra tất cả endpoint đều được bảo vệ**

```bash
# Endpoint deployments
curl -o /dev/null -w "%{http_code}\n" \
     http://127.0.0.1:8080/api/namespaces/default/deployments

# Endpoint tạo policy
curl -o /dev/null -w "%{http_code}\n" \
     -X POST http://127.0.0.1:8080/api/policies \
     -H "Content-Type: application/json" \
     -d '{}'
```

Cả hai đều phải trả `401`.

**Bước 6: Kiểm tra trang web chính (không cần auth)**

```bash
curl -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/
```

Trả `200` vì trang HTML không cần auth — auth chỉ áp dụng cho `/api/*`.

**Câu hỏi tự kiểm tra:**
1. Tại sao `Authorization: Basic <token>` không an toàn trên HTTP thuần?
2. Sự khác nhau giữa 401 và 403 là gì?
3. Tại sao server trả cùng 1 thông báo lỗi dù sai username hay sai password?

---

## Lab 02 — Khám Phá Deployment

### Mục tiêu học tập
Hiểu cách vArmor xác định deployment nào được bảo vệ, và tại sao dùng **label** để đánh dấu.

### Lý thuyết

**Label trong Kubernetes là gì?**

Label là cặp key-value gắn vào resource. Chúng không ảnh hưởng trực tiếp đến hành vi của K8s core, nhưng các controller (như vArmor) sử dụng chúng để xác định target.

```yaml
metadata:
  labels:
    sandbox.varmor.org/enable: "true"  # ← vArmor nhìn vào đây
    app: my-web-app
```

**Tại sao dùng label thay vì annotation hay tên deployment?**
- Label có thể được dùng trong `selector` — vArmor policy dùng selector để match pods
- Label là Kubernetes convention cho "thẻ phân loại"
- Annotation thường dùng cho metadata phi-operational

---

### Thực hành Lab 02

**Bước 1: Xem các deployment hiện có**

```bash
kubectl get deployments -A
```

**Bước 2: Gọi API để xem qua Console**

```bash
curl -s -u "admin:Admin@vArmor2026!" \
     http://127.0.0.1:8080/api/namespaces/default/deployments \
     | python3 -m json.tool
```

Chú ý trường `varmor_enabled` cho mỗi deployment. Hầu hết sẽ là `false`.

**Bước 3: Tạo deployment thử nghiệm**

```bash
kubectl create deployment lab02-test --image=nginx:alpine
```

**Tại sao dùng nginx:alpine?** Image nhỏ (~7MB so với nginx:latest ~140MB), phù hợp cho lab. Alpine Linux là distro tối giản, khởi động nhanh.

**Bước 4: Kiểm tra varmor_enabled ban đầu**

```bash
curl -s -u "admin:Admin@vArmor2026!" \
     http://127.0.0.1:8080/api/namespaces/default/deployments \
     | python3 -c "
import sys, json
data = json.load(sys.stdin)
for d in data['deployments']:
    if d['name'] == 'lab02-test':
        print('varmor_enabled:', d['varmor_enabled'])
"
```

Output: `varmor_enabled: False`

**Bước 5: Thêm label vArmor**

```bash
kubectl label deployment lab02-test sandbox.varmor.org/enable=true
```

**Bước 6: Kiểm tra lại**

```bash
curl -s -u "admin:Admin@vArmor2026!" \
     http://127.0.0.1:8080/api/namespaces/default/deployments \
     | python3 -c "
import sys, json
data = json.load(sys.stdin)
for d in data['deployments']:
    if d['name'] == 'lab02-test':
        print('varmor_enabled:', d['varmor_enabled'])
"
```

Output: `varmor_enabled: True`

**Bước 7: Xem raw label trong K8s để hiểu cơ chế**

```bash
kubectl get deployment lab02-test -o jsonpath='{.metadata.labels}' | python3 -m json.tool
```

**Bước 8: Xóa label và thấy thay đổi ngược lại**

```bash
kubectl label deployment lab02-test sandbox.varmor.org/enable-

curl -s -u "admin:Admin@vArmor2026!" \
     http://127.0.0.1:8080/api/namespaces/default/deployments \
     | python3 -c "
import sys, json
data = json.load(sys.stdin)
for d in data['deployments']:
    if d['name'] == 'lab02-test':
        print('After removing label:', d['varmor_enabled'])
"
```

**Bước 9: Dọn dẹp**

```bash
kubectl delete deployment lab02-test
```

**Câu hỏi tự kiểm tra:**
1. Vì sao Console không cache kết quả — mỗi lần gọi API là query K8s thật?
2. Nếu deployment có nhiều replica, label trên deployment có tự áp dụng lên pod không?
3. Khác nhau giữa `kubectl label` và sửa YAML trực tiếp?

---

## Lab 03 — Vòng Đời Policy (CRUD)

### Mục tiêu học tập
Hiểu cách VarmorPolicy được tạo, lưu trữ trong Kubernetes, và toàn bộ lifecycle từ tạo → xác minh → xóa.

### Lý thuyết

**VarmorPolicy là CRD — Custom Resource Definition**

Kubernetes cho phép bạn định nghĩa loại resource mới. Khi bạn `POST /api/policies`, Console:
1. Nhận JSON từ bạn
2. Dịch thành VarmorPolicy manifest
3. Gọi Kubernetes API để tạo resource
4. Kubernetes lưu vào etcd
5. vArmor manager watch và xử lý

```
Browser → Console API → K8s API Server → etcd (lưu trữ)
                                       → vArmor Manager (xử lý)
                                       → vArmor Agent (thực thi trên node)
```

**Tại sao không gọi K8s API trực tiếp từ browser?**
- K8s API cần certificate, không dùng được từ browser trực tiếp
- Console là **proxy** và **abstraction layer** — che giấu độ phức tạp K8s
- Console có thể thêm business logic (validation, audit log) trước khi gọi K8s

---

### Thực hành Lab 03

**Bước 1: Chuẩn bị deployment target**

```bash
kubectl create deployment lab03-target --image=nginx:alpine
```

**Bước 2: Tạo policy đơn giản qua API**

```bash
curl -s -u "admin:Admin@vArmor2026!" \
     -X POST http://127.0.0.1:8080/api/policies \
     -H "Content-Type: application/json" \
     -d '{
       "name": "my-first-policy",
       "namespace": "default",
       "target_deployment": "lab03-target",
       "enforcers": ["AppArmor"],
       "rules": [],
       "banned_files": []
     }' | python3 -m json.tool
```

**Hiểu tham số:**
- `enforcers`: Cơ chế enforcement — `AppArmor`, `Seccomp`, hoặc cả hai. Chọn AppArmor vì đây là LSM phổ biến nhất trên Ubuntu/Debian
- `rules`: built-in attack protection rules (rỗng = không chặn gì đặc biệt)
- `banned_files`: Danh sách file cụ thể bị cấm đọc/ghi

**Bước 3: Xác minh resource thật trong K8s**

```bash
# Liệt kê VarmorPolicy
kubectl get varmorpolicies -n default

# Xem chi tiết YAML
kubectl get varmorpolicy my-first-policy -n default -o yaml
```

**Đọc và hiểu YAML output:**
```yaml
spec:
  target:
    kind: Deployment
    name: lab03-target       # ← deployment được bảo vệ
  policy:
    enforcer: AppArmor       # ← cơ chế LSM
    mode: EnhanceProtect     # ← chế độ (quan trọng: "Enhance" không phải "Enhanced")
    enhanceProtect:          # ← (quan trọng: "enhance" không phải "enhanced")
      attackProtectionRules: []
```

**Tại sao mode là `EnhanceProtect` chứ không phải `Enforce`?**
vArmor có nhiều mode:
- `AlwaysAllow`: Không chặn gì (dùng để observe)
- `RuntimeDefault`: Áp dụng profile mặc định của container runtime
- `EnhanceProtect`: Áp dụng các rule tùy chỉnh — đây là mode chúng ta dùng

**Bước 4: Tạo policy với đầy đủ rules**

```bash
curl -s -u "admin:Admin@vArmor2026!" \
     -X POST http://127.0.0.1:8080/api/policies \
     -H "Content-Type: application/json" \
     -d '{
       "name": "my-full-policy",
       "namespace": "default",
       "target_deployment": "lab03-target",
       "enforcers": ["AppArmor"],
       "rules": ["container_escape", "privilege_escalation"],
       "banned_files": ["/etc/shadow", "/etc/passwd"]
     }' | python3 -m json.tool
```

**Bước 5: So sánh 2 policy để thấy sự khác nhau**

```bash
# Policy không có rules
kubectl get varmorpolicy my-first-policy -n default \
  -o jsonpath='{.spec.policy.enhanceProtect.attackProtectionRules}'

# Policy có rules
kubectl get varmorpolicy my-full-policy -n default \
  -o jsonpath='{.spec.policy.enhanceProtect.attackProtectionRules}' \
  | python3 -m json.tool
```

Bạn sẽ thấy `my-full-policy` chứa các rule cụ thể như `disallow-write-core-pattern`.

**Bước 6: Kiểm tra validation — thử tạo policy thiếu field**

```bash
# Thiếu 'name'
curl -v -u "admin:Admin@vArmor2026!" \
     -X POST http://127.0.0.1:8080/api/policies \
     -H "Content-Type: application/json" \
     -d '{"namespace":"default","target_deployment":"nginx","enforcers":["AppArmor"]}' \
     2>&1 | grep "HTTP\|error"
```

Server trả `400 Bad Request`. **Tại sao validation quan trọng?**
- Ngăn tạo resource không hợp lệ trong K8s (sẽ bị reject bởi K8s API dù sao)
- Trả về thông báo lỗi rõ ràng cho người dùng thay vì K8s raw error
- Defense in depth — validate ở cả application layer và K8s layer

**Bước 7: Xóa policy và xác minh**

```bash
# Xóa qua Console API
curl -v -u "admin:Admin@vArmor2026!" \
     -X DELETE http://127.0.0.1:8080/api/namespaces/default/policies/my-first-policy

# Xác minh không còn trong K8s
kubectl get varmorpolicy my-first-policy -n default
```

Output: `Error from server (NotFound)` — đúng như mong đợi.

**Bước 8: Thử xóa policy không tồn tại**

```bash
curl -v -u "admin:Admin@vArmor2026!" \
     -X DELETE http://127.0.0.1:8080/api/namespaces/default/policies/does-not-exist
```

Trả `404 Not Found`. **Tại sao quan trọng?** API cần phân biệt:
- `200`: Xóa thành công
- `404`: Resource không tồn tại (idempotent DELETE nên trả 404 không phải 200)
- `500`: Lỗi server thật

**Bước 9: Dọn dẹp**

```bash
kubectl delete varmorpolicy my-full-policy -n default
kubectl delete deployment lab03-target
```

---

## Lab 04 — Chặn File Nhạy Cảm

### Mục tiêu học tập
Hiểu cơ chế **AppArmor file rules**, tại sao một số file hệ thống nguy hiểm, và cách `appArmorRawRules` hoạt động.

### Lý thuyết

**Tại sao chặn /etc/shadow và /etc/passwd?**

```
/etc/passwd  → Danh sách user, UID, shell — attacker dùng để enumerate users
/etc/shadow  → Password hash (encrypted!) — attacker dùng để offline crack
```

Nếu container có thể đọc `/etc/shadow` của host (qua path traversal hoặc volume mount), attacker có thể copy hash về và crack offline với hashcat/john.

**Tại sao chặn /proc/sys/kernel/core_pattern?**

Đây là một trong những vector container escape nguy hiểm nhất (CVE-2022-0492):
```bash
# Bên trong container:
echo "| /tmp/evil_script" > /proc/sys/kernel/core_pattern
# → Khi bất kỳ process nào crash, kernel chạy /tmp/evil_script với quyền ROOT trên HOST
```

**AppArmor deny rule syntax:**
```
deny /path/to/file rwmlk,
```
- `r` = read, `w` = write, `m` = mmap (execute từ file), `l` = link, `k` = lock
- `deny` = chặn tuyệt đối (override bất kỳ allow nào)
- `,` ở cuối = cú pháp AppArmor yêu cầu

**Tại sao vArmor dùng `appArmorRawRules` thay vì `fileRules`?**

Kiểm tra CRD schema:
```bash
kubectl get crd varmorpolicies.crd.varmor.org \
  -o jsonpath='{.spec.versions[0].schema.openAPIV3Schema.properties.spec.properties.policy.properties.enhanceProtect.properties}' \
  | python3 -m json.tool | grep -A2 '"appArmor'
```

`fileRules` không tồn tại trong CRD schema — `appArmorRawRules` là field thật, nhận raw AppArmor profile fragment.

---

### Thực hành Lab 04

**Bước 1: Tạo deployment target**

```bash
kubectl create deployment lab04-target --image=ubuntu:22.04 -- sleep infinity
```

**Tại sao dùng ubuntu:22.04 thay vì nginx?** Ubuntu có shell đầy đủ để thử các lệnh tấn công. nginx chỉ có shell tối giản.

**Tại sao `-- sleep infinity`?** Container cần process foreground để không tự exit. `sleep infinity` giữ container sống mà không làm gì.

**Bước 2: Tạo policy với banned files**

```bash
curl -s -u "admin:Admin@vArmor2026!" \
     -X POST http://127.0.0.1:8080/api/policies \
     -H "Content-Type: application/json" \
     -d '{
       "name": "lab04-banned-policy",
       "namespace": "default",
       "target_deployment": "lab04-target",
       "enforcers": ["AppArmor"],
       "rules": [],
       "banned_files": [
         "/etc/shadow",
         "/etc/passwd",
         "/proc/sys/kernel/core_pattern",
         "/proc/sysrq-trigger"
       ]
     }' | python3 -m json.tool
```

**Bước 3: Xem AppArmor rule được tạo trong CRD**

```bash
kubectl get varmorpolicy lab04-banned-policy -n default \
  -o jsonpath='{.spec.policy.enhanceProtect.appArmorRawRules}' \
  | python3 -m json.tool
```

**Output mong đợi:**
```json
[
  {"rules": "deny /etc/shadow rwmlk,"},
  {"rules": "deny /etc/passwd rwmlk,"},
  {"rules": "deny /proc/sys/kernel/core_pattern rwmlk,"},
  {"rules": "deny /proc/sysrq-trigger rwmlk,"}
]
```

Đây là raw AppArmor profile syntax — vArmor agent sẽ compile thành AppArmor profile và load vào kernel.

**Bước 4: Lấy tên pod**

```bash
POD=$(kubectl get pods -l app=lab04-target -o jsonpath='{.items[0].metadata.name}')
echo "Pod name: $POD"
```

**Bước 5: Kiểm tra xem varmor-agent có đang chạy không**

```bash
kubectl get pods -n varmor -l app=varmor-agent \
  -o jsonpath='{.items[0].status.containerStatuses[0].ready}'
```

Nếu output là `true`: policy được enforce thực sự.  
Nếu output là `false` hoặc không có: agent không chạy, policy được tạo trong K8s nhưng không được load vào AppArmor kernel.

**Bước 6a (nếu agent ready): Thử tấn công thực tế**

```bash
# Thử đọc /etc/shadow
kubectl exec $POD -- cat /etc/shadow

# Thử ghi /etc/passwd
kubectl exec $POD -- sh -c 'echo "hacker:x:0:0::/root:/bin/bash" >> /etc/passwd'

# Thử ghi core_pattern
kubectl exec $POD -- sh -c 'echo "| /tmp/evil" > /proc/sys/kernel/core_pattern'
```

Tất cả phải trả `Permission denied` hoặc `Operation not permitted`.

**Bước 6b (nếu agent không ready): Đọc profile được tạo**

```bash
# Xem toàn bộ policy spec
kubectl get varmorpolicy lab04-banned-policy -n default -o yaml
```

Quan sát `enhanceProtect.appArmorRawRules` chứa đúng các deny rule.

**Bước 7: Kiểm tra file BÌNH THƯỜNG vẫn truy cập được**

```bash
kubectl exec $POD -- cat /etc/hostname
kubectl exec $POD -- cat /etc/os-release
```

Nếu những file này vẫn đọc được, policy đúng (chỉ chặn file trong danh sách, không chặn tất cả).

**Bước 8: Dọn dẹp**

```bash
kubectl delete varmorpolicy lab04-banned-policy -n default
kubectl delete deployment lab04-target
```

---

## Lab 05 — Ngăn Container Escape

### Mục tiêu học tập
Hiểu các kỹ thuật **container escape** nguy hiểm nhất và cách vArmor ngăn chặn chúng.

### Lý thuyết

#### Tấn công 1: Core Pattern Escape (CVE-2022-0492)

```
Trong container (với quyền root container):
1. Ghi /proc/sys/kernel/core_pattern = "| /tmp/evil %s"
2. Crash bất kỳ process nào trong bất kỳ container nào
3. Kernel HOST chạy /tmp/evil với quyền root TRÊN HOST
→ Attacker đã thoát khỏi container!
```

**Tại sao hoạt động?** `/proc/sys/kernel/core_pattern` là kernel parameter toàn cục — không bị namespaced. Container có namespace riêng cho PID, network, mount... nhưng **kernel parameters** được chia sẻ với host.

#### Tấn công 2: Release Agent (CVE-2022-0492 — variant)

```
1. Mount cgroup filesystem vào /tmp/cg
2. Tạo subdirectory cgroup
3. Ghi /tmp/evil vào release_agent
4. Set notify_on_release = 1
5. Khi process trong cgroup exit → kernel HOST chạy /tmp/evil
```

#### Tấn công 3: User Namespace Privilege Escalation

```bash
# Trong container:
unshare --user --map-root-user /bin/bash
# → Process hiện tại "thấy" mình là UID 0 trong namespace mới
# → Có thể thực hiện một số thao tác restricted
```

**Tại sao nguy hiểm?** Kết hợp với các bug kernel khác, việc vào được user namespace mới có thể là bước đầu của leo thang đặc quyền.

#### Cơ chế phòng thủ của vArmor

vArmor sử dụng AppArmor rules để chặn **chính xác các syscall và file access** cần thiết cho những cuộc tấn công này:

| Rule | Chặn gì |
|---|---|
| `disallow-write-core-pattern` | Ghi vào `/proc/sys/kernel/core_pattern` |
| `disallow-mount-securityfs` | Mount securityfs (expose AppArmor admin interface) |
| `disallow-write-release-agent` | Ghi vào `release_agent` trong cgroup |
| `disallow-abuse-user-ns` | Tạo user namespace mới (`unshare --user`) |
| `disable-cap-privilege` | Tắt các Linux capability nguy hiểm |

---

### Thực hành Lab 05

**Bước 1: Tạo deployment**

```bash
kubectl create deployment lab05-target --image=ubuntu:22.04 -- sleep infinity
```

**Bước 2: Tạo policy ngăn container escape**

```bash
curl -s -u "admin:Admin@vArmor2026!" \
     -X POST http://127.0.0.1:8080/api/policies \
     -H "Content-Type: application/json" \
     -d '{
       "name": "lab05-escape-policy",
       "namespace": "default",
       "target_deployment": "lab05-target",
       "enforcers": ["AppArmor"],
       "rules": ["container_escape", "privilege_escalation"],
       "banned_files": []
     }' | python3 -m json.tool
```

**Bước 3: Xác minh rules trong CRD**

```bash
kubectl get varmorpolicy lab05-escape-policy -n default \
  -o jsonpath='{.spec.policy.enhanceProtect.attackProtectionRules}' \
  | python3 -m json.tool
```

**Bạn phải thấy:**
```json
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
```

**Giải thích cấu trúc:** `attackProtectionRules` là array của object, mỗi object có `rules` (array string) và optionally `targets` (chỉ áp dụng cho process cụ thể). Không có field `action` — mặc định là `deny`.

**Bước 4: Tìm pod và thử tấn công**

```bash
POD=$(kubectl get pods -l app=lab05-target -o jsonpath='{.items[0].metadata.name}')

# Kiểm tra agent status
AGENT_READY=$(kubectl get pods -n varmor -l app=varmor-agent \
  -o jsonpath='{.items[0].status.containerStatuses[0].ready}' 2>/dev/null)
echo "Agent ready: $AGENT_READY"
```

**Nếu agent ready — thử tấn công thực sự:**

```bash
# Tấn công 1: Core pattern escape
kubectl exec $POD -- sh -c 'echo "| /tmp/evil" > /proc/sys/kernel/core_pattern 2>&1'
# Kết quả mong đợi: "sh: echo: write error: Permission denied"

# Tấn công 2: Mount securityfs
kubectl exec $POD -- mount -t securityfs securityfs /tmp/sf 2>&1
# Kết quả mong đợi: "mount: /tmp/sf: permission denied."

# Tấn công 3: User namespace unshare
kubectl exec $POD -- unshare --user --map-root-user whoami 2>&1
# Kết quả mong đợi: "unshare: unshare failed: Operation not permitted"
```

**Nếu agent không ready — đọc giao thức tấn công để học lý thuyết:**

```bash
# Đây là những gì attacker sẽ chạy nếu không có protection:
echo "Attack 1 - Core pattern:"
echo "  echo '| /tmp/evil' > /proc/sys/kernel/core_pattern"
echo "  # Sau đó crash 1 process: kill -SIGSEGV \$\$"

echo ""
echo "Attack 2 - Release agent:"
echo "  mkdir /tmp/cg && mount -t cgroup cgroup /tmp/cg"
echo "  mkdir /tmp/cg/x && echo 1 > /tmp/cg/x/notify_on_release"
echo "  echo '#!/bin/bash\nid > /tmp/pwned' > /tmp/evil && chmod +x /tmp/evil"
echo "  echo /tmp/evil > /tmp/cg/release_agent"
echo "  # Khi process exit, /tmp/evil chạy với quyền host root"
```

**Bước 5: So sánh policy có và không có protection**

```bash
# Tạo deployment KHÔNG có protection
kubectl create deployment lab05-unprotected --image=ubuntu:22.04 -- sleep infinity
POD_UNPROTECTED=$(kubectl get pods -l app=lab05-unprotected \
  -o jsonpath='{.items[0].metadata.name}')

# Thử core_pattern trên deployment không được bảo vệ
if [ -n "$AGENT_READY" ] && [ "$AGENT_READY" = "true" ]; then
    echo "--- Protected pod ---"
    kubectl exec $POD -- sh -c 'echo "test" > /proc/sys/kernel/core_pattern 2>&1' || echo "BLOCKED (good)"
    
    echo "--- Unprotected pod ---"
    kubectl exec $POD_UNPROTECTED -- sh -c 'echo "test" > /proc/sys/kernel/core_pattern 2>&1' || echo "allowed (dangerous!)"
fi

# Dọn dẹp
kubectl delete deployment lab05-unprotected
```

**Bước 6: Dọn dẹp**

```bash
kubectl delete varmorpolicy lab05-escape-policy -n default
kubectl delete deployment lab05-target
```

---

## Lab 06 — Audit Log

### Mục tiêu học tập
Hiểu tại sao **audit logging** quan trọng trong security operations, format log chuẩn, và cách thu thập trong K8s.

### Lý thuyết

**Tại sao cần audit log?**

Trong security, nguyên tắc là **assume breach** — giả định hệ thống đã bị xâm phạm. Khi đó bạn cần trả lời:
- *Ai* đã làm gì?
- *Khi nào*?
- *Thành công hay thất bại*?

Audit log trả lời những câu hỏi này để **incident response** và **forensics**.

**Format log của chúng ta:**
```
[TIMESTAMP_ISO8601] [AUDIT] user=X action=Y policy=Z namespace=N status=S details="..."
```

**Tại sao dùng format key=value thay vì JSON?**
- Dễ `grep` với công cụ đơn giản
- Tương thích với Fluentd, Logstash, Vector để parse tự động
- Ít overhead hơn serializing JSON cho mỗi log line
- Standard trong syslog world (logfmt format)

**Tại sao log ra STDOUT thay vì file?**

Đây là **12-Factor App principle** #11 (Logs):
- Container không có state — log vào file sẽ mất khi pod restart
- Kubernetes thu thập STDOUT/STDERR từ mọi pod tự động
- Log collectors (Fluentd, Filebeat) đọc từ `/var/log/containers/*.log`

---

### Thực hành Lab 06

**Bước 1: Lấy tên Console pod**

```bash
CONSOLE_POD=$(kubectl get pods -l app=varmor-console \
  -o jsonpath='{.items[0].metadata.name}')
echo "Console pod: $CONSOLE_POD"
```

**Bước 2: Xem toàn bộ log hiện tại của Console**

```bash
kubectl logs $CONSOLE_POD | tail -20
```

Bạn sẽ thấy cả:
- Gunicorn access log: `GET /api/... 200`
- Audit log: `[TIMESTAMP] [AUDIT] user=admin action=...`

**Bước 3: Follow log real-time trong một terminal**

```bash
# Terminal 1: follow log
kubectl logs -f $CONSOLE_POD | grep '\[AUDIT\]'
```

Giữ terminal này mở, mở terminal thứ 2.

**Bước 4: Thực hiện action và quan sát log (Terminal 2)**

```bash
# Terminal 2: SSH vào server và tạo policy
kubectl create deployment lab06-target --image=nginx:alpine

curl -s -u "admin:Admin@vArmor2026!" \
     -X POST http://127.0.0.1:8080/api/policies \
     -H "Content-Type: application/json" \
     -d '{
       "name": "lab06-test-policy",
       "namespace": "default",
       "target_deployment": "lab06-target",
       "enforcers": ["AppArmor"],
       "rules": [],
       "banned_files": []
     }'
```

**Quan sát Terminal 1 ngay lập tức xuất hiện:**
```
[2026-05-13T16:41:31Z] [AUDIT] user=admin action=CREATE policy=lab06-test-policy namespace=default status=SUCCESS
```

**Bước 5: Phân tích format timestamp**

```bash
# Lấy một dòng AUDIT log
kubectl logs $CONSOLE_POD | grep '\[AUDIT\]' | tail -1
```

Format `[2026-05-13T16:41:31Z]`:
- `T` phân cách ngày và giờ (ISO 8601)
- `Z` = UTC timezone (Zulu time)

**Tại sao UTC?** Log từ nhiều timezone khác nhau — nếu dùng local time sẽ không thể correlate. UTC là standard cho logs.

**Bước 6: Test FAILURE log**

```bash
# Tạo policy trùng tên (sẽ bị 409 Conflict)
curl -s -u "admin:Admin@vArmor2026!" \
     -X POST http://127.0.0.1:8080/api/policies \
     -H "Content-Type: application/json" \
     -d '{
       "name": "lab06-test-policy",
       "namespace": "default",
       "target_deployment": "lab06-target",
       "enforcers": ["AppArmor"],
       "rules": [],
       "banned_files": []
     }'
```

**Quan sát Terminal 1:**
```
[2026-05-13T16:42:24Z] [AUDIT] user=admin action=CREATE policy=lab06-test-policy namespace=default status=FAILURE details="Conflict"
```

**Tại sao log cả FAILURE?** Security audit cần biết cả các **attempt thất bại** — thất bại nhiều lần liên tiếp có thể là dấu hiệu brute-force hoặc misconfiguration.

**Bước 7: Test DELETE log**

```bash
curl -s -u "admin:Admin@vArmor2026!" \
     -X DELETE http://127.0.0.1:8080/api/namespaces/default/policies/lab06-test-policy
```

**Bước 8: Lọc và phân tích log**

```bash
# Chỉ xem AUDIT logs
kubectl logs $CONSOLE_POD | grep '\[AUDIT\]'

# Đếm số action CREATE
kubectl logs $CONSOLE_POD | grep '\[AUDIT\]' | grep 'action=CREATE' | wc -l

# Xem chỉ FAILURE events
kubectl logs $CONSOLE_POD | grep '\[AUDIT\]' | grep 'status=FAILURE'

# Xem logs trong 5 phút gần nhất
kubectl logs $CONSOLE_POD --since=5m | grep '\[AUDIT\]'
```

**Bước 9: Hiểu cách log collector hoạt động**

```bash
# Xem log file thật trong filesystem của node Kind
docker exec varmor-lab-control-plane \
  ls /var/log/containers/ | grep varmor-console
```

Đây là nơi Fluentd/Filebeat đọc log trong production.

**Bước 10: Dọn dẹp**

```bash
kubectl delete deployment lab06-target
```

---

## Lab 07 — RBAC & Phân Quyền

### Mục tiêu học tập
Hiểu **Kubernetes RBAC**, nguyên tắc **Least Privilege**, và tại sao ServiceAccount cần được cấu hình cẩn thận.

### Lý thuyết

**RBAC trong Kubernetes hoạt động thế nào?**

```
ServiceAccount (danh tính)
    │
    ▼
ClusterRoleBinding (liên kết)
    │
    ▼
ClusterRole (tập quyền)
    │
    ├── apiGroups: ["apps"]
    │   resources: ["deployments"]
    │   verbs: ["get", "list", "watch"]    ← Chỉ đọc
    │
    └── apiGroups: ["crd.varmor.org"]
        resources: ["varmorpolicies"]
        verbs: ["get","list","watch","create","update","patch","delete"]  ← Toàn quyền
```

**Tại sao cần ServiceAccount riêng cho Console?**

Nếu Console dùng `default` ServiceAccount (mặc định), nó kế thừa quyền của default SA — thường là không có quyền gì, hoặc trong môi trường cũ có thể có quá nhiều quyền. SA riêng đảm bảo **explicit permission grant**.

**Principle of Least Privilege:**
Console CHỈ cần:
- `get/list/watch deployments` — để hiển thị danh sách
- `CRUD varmorpolicies` — để quản lý policy

Console KHÔNG cần:
- Đọc/ghi Secrets (nguy hiểm nếu bị compromise)
- Tạo/xóa Deployments
- Xóa Nodes hay Namespaces
- Đọc ClusterRoles (leo thang quyền)

---

### Thực hành Lab 07

**Bước 1: Xem ServiceAccount của Console**

```bash
kubectl get serviceaccount varmor-console-sa -n default -o yaml
```

Chú ý không có secrets attached riêng — token được inject tự động vào pod.

**Bước 2: Xem ClusterRole**

```bash
kubectl get clusterrole varmor-console-role -o yaml
```

**Đọc và hiểu từng rule:**
```yaml
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch"]
  # → Chỉ đọc deployment, không thể tạo/xóa/sửa

- apiGroups: ["crd.varmor.org"]
  resources: ["varmorpolicies"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  # → Toàn quyền với VarmorPolicy vì Console cần quản lý chúng
```

**Bước 3: Xem ClusterRoleBinding**

```bash
kubectl get clusterrolebinding varmor-console-binding -o yaml
```

```yaml
subjects:
- kind: ServiceAccount
  name: varmor-console-sa    # ← SA nào được cấp quyền
  namespace: default         # ← SA trong namespace nào
roleRef:
  kind: ClusterRole
  name: varmor-console-role  # ← Được cấp role nào
```

**Bước 4: Test quyền trực tiếp với kubectl auth can-i**

```bash
SA="system:serviceaccount:default:varmor-console-sa"

# Quyền ĐƯỢC PHÉP
echo "=== Quyên duoc phep ==="
kubectl auth can-i get deployments --as="$SA" --all-namespaces
kubectl auth can-i list deployments --as="$SA" --all-namespaces
kubectl auth can-i create varmorpolicies.crd.varmor.org --as="$SA" --all-namespaces
kubectl auth can-i delete varmorpolicies.crd.varmor.org --as="$SA" --all-namespaces

# Quyền BỊ CẤM
echo "=== Quyen bi cam ==="
kubectl auth can-i delete deployments --as="$SA" --all-namespaces
kubectl auth can-i get secrets --as="$SA" --all-namespaces
kubectl auth can-i create pods --as="$SA" --all-namespaces
kubectl auth can-i delete nodes --as="$SA" --all-namespaces
kubectl auth can-i get clusterroles --as="$SA" --all-namespaces
```

**Kết quả mong đợi:** `yes` cho nhóm đầu, `no` cho nhóm sau.

**`kubectl auth can-i` hoạt động thế nào?** Nó gọi `SubjectAccessReview` API — API của K8s để kiểm tra quyền mà không cần thực hiện action thật. Rất hữu ích cho security audit.

**Bước 5: Kiểm tra pod đang dùng đúng ServiceAccount**

```bash
kubectl get pods -l app=varmor-console \
  -o jsonpath='{.items[0].spec.serviceAccountName}'
```

Output phải là `varmor-console-sa`.

**Bước 6: Kiểm tra security context của container**

```bash
kubectl get pods -l app=varmor-console -o json \
  | python3 -c "
import sys, json
pod = json.load(sys.stdin)['items'][0]
spec = pod['spec']
print('Pod securityContext:', spec.get('securityContext', {}))
container = spec['containers'][0]
print('Container securityContext:', container.get('securityContext', {}))
"
```

**Bạn sẽ thấy:**
```python
Container securityContext: {
  'allowPrivilegeEscalation': False,  # ← không thể sudo/setuid
  'capabilities': {'drop': ['ALL']},  # ← drop tất cả Linux capabilities
  'runAsNonRoot': True,               # ← không chạy với UID 0
  'runAsUser': 999                    # ← chạy với UID cụ thể
}
```

**Tại sao `drop: ALL` capabilities?**

Linux capabilities chia quyền root thành ~40 capabilities riêng biệt (CAP_NET_ADMIN, CAP_SYS_PTRACE...). Drop tất cả và chỉ thêm lại những gì cần = least privilege.

**Bước 7: Thử thực sự lấy token và call K8s API**

```bash
# Lấy token của Console pod
CONSOLE_POD=$(kubectl get pods -l app=varmor-console \
  -o jsonpath='{.items[0].metadata.name}')

TOKEN=$(kubectl exec $CONSOLE_POD -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/tmp/ca.crt
kubectl exec $CONSOLE_POD -- cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt > $CACERT
K8S_API=$(kubectl cluster-info | grep "control plane" | awk '{print $NF}')

echo "K8s API: $K8S_API"

# Thử list deployments (PHẢI được phép)
curl -s --cacert $CACERT \
     -H "Authorization: Bearer $TOKEN" \
     "$K8S_API/apis/apps/v1/namespaces/default/deployments" \
     | python3 -m json.tool | head -20

echo "---"

# Thử list secrets (PHẢI bị từ chối)
curl -s --cacert $CACERT \
     -H "Authorization: Bearer $TOKEN" \
     "$K8S_API/api/v1/namespaces/default/secrets" \
     | python3 -m json.tool
```

Thử list secrets sẽ trả `403 Forbidden` với message rõ ràng:
```json
{"message": "secrets is forbidden: User \"system:serviceaccount:default:varmor-console-sa\" cannot list resource..."}
```

**Đây là RBAC đang làm việc** — token thật của Console không thể đọc Secrets.

**Bước 8: So sánh với scenario KHÔNG có RBAC**

Nếu Console dùng `cluster-admin` ClusterRole:
```bash
# (CHỈ ĐỂ MINH HỌA - KHÔNG CHẠY)
# kubectl auth can-i '*' '*' --as="system:serviceaccount:default:varmor-console-sa" --all-namespaces
# → yes (có thể làm MỌI THỨ)
```

Nếu Console bị compromise với cluster-admin, attacker có thể:
- Đọc tất cả Secrets (bao gồm credentials của service khác)
- Tạo pod với quyền root
- Xóa toàn bộ cluster
- Tạo ClusterRoleBinding mới để duy trì quyền

---

## Phần Tổng Kết

### Tổng hợp những gì bạn đã học

| Lab | Concept | Lesson |
|---|---|---|
| 01 | Basic Auth | API phải được bảo vệ; 401 vs 403; không leak thông tin |
| 02 | K8s Labels | Labels là mechanism classification, không affect behavior trực tiếp |
| 03 | K8s CRD | Console là proxy layer; CRD extend K8s API; lifecycle resource |
| 04 | AppArmor file rules | deny syntax; rwmlk permissions; /proc/* nguy hiểm |
| 05 | Container escape | Kernel params không namespaced; CVE-2022-0492 mechanics |
| 06 | Audit logging | STDOUT logging; ISO8601; log FAILURE cũng quan trọng |
| 07 | RBAC | Least privilege; ServiceAccount; auth can-i audit; drop capabilities |

### Câu hỏi để suy nghĩ thêm

1. **Lab 01**: Nếu HTTPS bị disabled, Basic Auth có an toàn không? Tại sao?
2. **Lab 03**: Tại sao Console cần tạo CRD thay vì để user tự kubectl apply?
3. **Lab 04**: `deny /etc/shadow rwmlk,` chặn cả process nào trong container? Có exception không?
4. **Lab 05**: Tại sao container escape nguy hiểm hơn trong K8s cluster so với single VM?
5. **Lab 06**: Audit log giúp ích gì khi đã bị tấn công (forensics)?
6. **Lab 07**: Nếu Console pod bị attacker kiểm soát, họ có thể làm gì với quyền hiện tại?

### Bước tiếp theo

- **Nâng cao Lab 04-05**: Cài cluster với AppArmor kernel support thực sự (GKE, EKS, bare metal Ubuntu)
- **Thêm Seccomp**: Kết hợp AppArmor + Seccomp để defense in depth
- **Log aggregation**: Kết nối với Grafana Loki để visualize audit logs
- **VarmorClusterPolicy**: Áp dụng policy cho toàn cluster thay vì per-namespace
- **eBPF enforcer**: Thử vArmor với eBPF thay vì AppArmor — linh hoạt hơn, không cần LSM

### Chạy lại automated tests để xác nhận kiến thức

Sau khi tự lab, chạy automated test để xác nhận environment vẫn clean:

```bash
cd /opt/varmor-console
bash labs/run_all_labs.sh
```

Nếu tất cả PASS, môi trường lab vẫn đang hoạt động đúng.

---

*Hướng dẫn này được thiết kế để học bảo mật container từ nền tảng. Mỗi khái niệm được giải thích từ "tại sao" trước khi đến "làm thế nào".*
