import datetime
import logging
import re

from flask import Blueprint, jsonify, request
from kubernetes.client.rest import ApiException

from ..audit import audit_logger
from ..auth import get_current_user, require_auth
from ..k8s_client import (
    VARMOR_GROUP,
    VARMOR_PLURAL,
    VARMOR_VERSION,
    apps_v1,
    custom_objects,
)

logger = logging.getLogger(__name__)
api_bp = Blueprint("api", __name__, url_prefix="/api")

# Rule sets keyed by category (from docs/guides/policies_and_rules/built_in_rules.md)
HARDENING_RULES = frozenset([
    "disallow-write-core-pattern", "disallow-mount-securityfs", "disallow-mount-procfs",
    "disallow-write-release-agent", "disallow-mount-cgroupfs", "disallow-debug-disk-device",
    "disallow-mount-disk-device", "disallow-mount", "disallow-umount", "disallow-insmod",
    "disallow-load-bpf-prog", "disallow-access-procfs-root", "disallow-access-kallsyms",
    "disable-cap-all", "disable-cap-all-except-net-bind-service", "disable-cap-privileged",
    "disallow-abuse-user-ns", "disallow-create-user-ns", "disallow-load-all-bpf-prog",
    "disallow-load-bpf-via-setsockopt", "disallow-userfaultfd-creation",
])

ATTACK_RULES = frozenset([
    "mitigate-sa-leak", "mitigate-disk-device-number-leak", "mitigate-overlayfs-leak",
    "mitigate-host-ip-leak", "block-access-to-metadata-service",
    "block-access-to-aws-metadata-service", "block-access-to-volc-metadata-service",
    "block-access-to-alibaba-metadata-service", "block-access-to-oci-metadata-service",
    "disable-write-etc", "disable-access-passwd", "disable-access-shadow",
    "disable-access-ssh-dir", "disable-write-skills", "disable-busybox", "disable-shell",
    "disable-wget", "disable-curl", "disable-chmod", "disable-chmod-x-bit",
    "disable-chmod-s-bit", "disable-su-sudo", "disable-network", "disable-inet",
    "disable-ipv4", "disable-inet6", "disable-ipv6", "disable-unix-domain-socket",
    "disable-icmp", "disable-tcp", "disable-udp", "block-access-to-kube-apiserver",
    "block-access-to-container-runtime",
])

VULN_RULES = frozenset([
    "cgroups-lxcfs-escape-mitigation", "runc-override-mitigation", "dirty-pipe-mitigation",
    "ingress-nightmare-mitigation", "copy-fail-mitigation",
])

VALID_MODES = frozenset(["AlwaysAllow", "RuntimeDefault", "EnhanceProtect", "BehaviorModeling", "DefenseInDepth"])
VALID_KINDS = frozenset(["Deployment", "StatefulSet", "DaemonSet", "Pod"])


# ---------------------------------------------------------------------------
# Deployments sidebar (unchanged endpoint, keeps backward compat)
# ---------------------------------------------------------------------------

@api_bp.route("/namespaces/<namespace>/deployments", methods=["GET"])
@require_auth
def list_deployments(namespace: str):
    try:
        result = apps_v1().list_namespaced_deployment(namespace=namespace)
    except ApiException as exc:
        logger.error("K8s error listing deployments in %s: %s", namespace, exc)
        return jsonify({"error": f"Kubernetes API error {exc.status}: {exc.reason}"}), exc.status
    except Exception as exc:
        logger.exception("Unexpected error listing deployments in %s", namespace)
        return jsonify({"error": str(exc)}), 500

    deployments = []
    for dep in result.items:
        meta_labels = dep.metadata.labels or {}
        pod_labels = (
            (dep.spec.template.metadata.labels or {})
            if dep.spec.template and dep.spec.template.metadata
            else {}
        )
        varmor_on = (
            meta_labels.get("sandbox.varmor.org/enable") == "true"
            or pod_labels.get("sandbox.varmor.org/enable") == "true"
        )
        deployments.append({
            "name": dep.metadata.name,
            "namespace": dep.metadata.namespace,
            "replicas": dep.spec.replicas or 0,
            "ready_replicas": dep.status.ready_replicas or 0,
            "varmor_enabled": varmor_on,
        })

    return jsonify({"deployments": deployments})


# ---------------------------------------------------------------------------
# Workloads – list by kind (for target dropdown in create form)
# ---------------------------------------------------------------------------

@api_bp.route("/namespaces/<namespace>/workloads", methods=["GET"])
@require_auth
def list_workloads(namespace: str):
    kind = request.args.get("kind", "Deployment")
    if kind not in VALID_KINDS:
        return jsonify({"error": f"Invalid kind '{kind}'"}), 400

    try:
        api = apps_v1()
        if kind == "Deployment":
            items = api.list_namespaced_deployment(namespace=namespace).items
        elif kind == "StatefulSet":
            items = api.list_namespaced_stateful_set(namespace=namespace).items
        elif kind == "DaemonSet":
            items = api.list_namespaced_daemon_set(namespace=namespace).items
        else:
            items = []

        workloads = []
        for item in items:
            meta_labels = item.metadata.labels or {}
            pod_labels = {}
            if (hasattr(item, "spec") and hasattr(item.spec, "template")
                    and item.spec.template and item.spec.template.metadata):
                pod_labels = item.spec.template.metadata.labels or {}

            varmor_on = (
                meta_labels.get("sandbox.varmor.org/enable") == "true"
                or pod_labels.get("sandbox.varmor.org/enable") == "true"
            )
            replicas = getattr(item.spec, "replicas", None) or 0
            status = item.status if hasattr(item, "status") else None
            ready_replicas = (
                getattr(status, "ready_replicas", None)
                or getattr(status, "number_ready", None)
                or 0
            ) if status else 0

            workloads.append({
                "name": item.metadata.name,
                "namespace": item.metadata.namespace,
                "kind": kind,
                "replicas": replicas,
                "ready_replicas": ready_replicas,
                "varmor_enabled": varmor_on,
            })

        return jsonify({"workloads": workloads})

    except ApiException as exc:
        logger.error("K8s error listing %s in %s: %s", kind, namespace, exc)
        return jsonify({"error": f"Kubernetes API error {exc.status}: {exc.reason}"}), exc.status
    except Exception as exc:
        logger.exception("Unexpected error listing %s in %s", kind, namespace)
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Policies – list
# ---------------------------------------------------------------------------

@api_bp.route("/namespaces/<namespace>/policies", methods=["GET"])
@require_auth
def list_policies(namespace: str):
    try:
        raw = custom_objects().list_namespaced_custom_object(
            group=VARMOR_GROUP,
            version=VARMOR_VERSION,
            namespace=namespace,
            plural=VARMOR_PLURAL,
        )
    except ApiException as exc:
        logger.error("K8s error listing policies in %s: %s", namespace, exc)
        return jsonify({"error": f"Kubernetes API error {exc.status}: {exc.reason}"}), exc.status
    except Exception as exc:
        logger.exception("Unexpected error listing policies in %s", namespace)
        return jsonify({"error": str(exc)}), 500

    policies = []
    for item in raw.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        conditions = item.get("status", {}).get("conditions", [])

        status = "Pending"
        for cond in conditions:
            if cond.get("type") == "Ready" and cond.get("status") == "True":
                status = "Ready"
                break

        policies.append({
            "name": meta.get("name", ""),
            "namespace": meta.get("namespace", namespace),
            "created_at": meta.get("creationTimestamp", ""),
            "status": status,
            "mode": spec.get("policy", {}).get("mode", "Unknown"),
            "enforcer": spec.get("policy", {}).get("enforcer", ""),
            "target": spec.get("target", {}),
        })

    return jsonify({"policies": policies})


# ---------------------------------------------------------------------------
# Policies – get single (detail view)
# ---------------------------------------------------------------------------

@api_bp.route("/namespaces/<namespace>/policies/<name>", methods=["GET"])
@require_auth
def get_policy(namespace: str, name: str):
    try:
        item = custom_objects().get_namespaced_custom_object(
            group=VARMOR_GROUP,
            version=VARMOR_VERSION,
            namespace=namespace,
            plural=VARMOR_PLURAL,
            name=name,
        )
        return jsonify(item)
    except ApiException as exc:
        logger.error("K8s error getting policy %s/%s: %s", namespace, name, exc)
        return jsonify({"error": f"Kubernetes API error {exc.status}: {exc.reason}"}), exc.status
    except Exception as exc:
        logger.exception("Unexpected error getting policy %s/%s", namespace, name)
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Policies – create
# ---------------------------------------------------------------------------

@api_bp.route("/policies", methods=["POST"])
@require_auth
def create_policy():
    user = get_current_user()
    body = request.get_json(silent=True)

    if not body:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    raw_name = (body.get("name") or "").strip()
    name = re.sub(r"[_\s]+", "-", raw_name.lower())
    name = re.sub(r"[^a-z0-9\-]", "", name)
    name = name.strip("-")

    namespace = (body.get("namespace") or "default").strip()
    target_workload = (body.get("target_deployment") or "").strip()
    target_kind = (body.get("target_kind") or "Deployment").strip()
    mode = (body.get("mode") or "EnhanceProtect").strip()
    enforcers: list = body.get("enforcers") or ["AppArmor"]
    rules: list = body.get("rules") or []
    banned_files: list = body.get("banned_files") or []
    modeling_duration: int = int(body.get("modeling_duration") or 3600)
    update_existing = bool(body.get("update_existing_workloads", False))
    audit_violations = bool(body.get("audit_violations", False))
    allow_violations = bool(body.get("allow_violations", False))

    if not name:
        return jsonify({"error": "Policy name is required and must contain at least one alphanumeric character"}), 400
    if len(name) > 63:
        return jsonify({"error": f"Policy name too long ({len(name)} chars); max 63 after sanitization"}), 400
    if not target_workload:
        return jsonify({"error": "Field 'target_deployment' is required"}), 400
    if mode not in VALID_MODES:
        return jsonify({"error": f"Invalid mode '{mode}'. Must be one of: {', '.join(sorted(VALID_MODES))}"}), 400
    if target_kind not in VALID_KINDS:
        return jsonify({"error": f"Invalid target_kind '{target_kind}'"}), 400

    enforcer_str = "|".join(enforcers) if enforcers else "AppArmor"

    spec_policy: dict = {"enforcer": enforcer_str, "mode": mode}

    if mode == "EnhanceProtect":
        hardening = [r for r in rules if r in HARDENING_RULES]
        attack = [r for r in rules if r in ATTACK_RULES]
        vuln = [r for r in rules if r in VULN_RULES]

        apparmor_raw = []
        for path in banned_files:
            p = path.strip()
            if p:
                apparmor_raw.append({"rules": f"deny {p} rwmlk,"})

        enhance_protect: dict = {}
        if hardening:
            enhance_protect["hardeningRules"] = hardening
        if attack:
            enhance_protect["attackProtectionRules"] = [{"rules": attack}]
        if vuln:
            enhance_protect["vulMitigationRules"] = vuln
        if apparmor_raw:
            enhance_protect["appArmorRawRules"] = apparmor_raw
        if audit_violations:
            enhance_protect["auditViolations"] = True
        if allow_violations:
            enhance_protect["allowViolations"] = True

        if not enhance_protect:
            return jsonify({"error": "EnhanceProtect policy must have at least one rule or banned file"}), 400

        spec_policy["enhanceProtect"] = enhance_protect

    elif mode == "BehaviorModeling":
        spec_policy["modelingOptions"] = {"duration": modeling_duration}

    manifest = {
        "apiVersion": f"{VARMOR_GROUP}/{VARMOR_VERSION}",
        "kind": "VarmorPolicy",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "updateExistingWorkloads": update_existing,
            "target": {"kind": target_kind, "name": target_workload},
            "policy": spec_policy,
        },
    }

    try:
        created = custom_objects().create_namespaced_custom_object(
            group=VARMOR_GROUP,
            version=VARMOR_VERSION,
            namespace=namespace,
            plural=VARMOR_PLURAL,
            body=manifest,
        )
        audit_logger.log(user, "CREATE", name, namespace, "SUCCESS")
        actual_name = created.get("metadata", {}).get("name", name)
        msg = f"Policy '{actual_name}' created successfully"
        if actual_name != raw_name:
            msg += f" (name sanitized from '{raw_name}')"
        return jsonify({"message": msg, "name": actual_name}), 201

    except ApiException as exc:
        audit_logger.log(user, "CREATE", name, namespace, "FAILURE", exc.reason or str(exc.status))
        logger.error("K8s error creating policy %s/%s: %s", namespace, name, exc)
        return jsonify({"error": f"Kubernetes API error {exc.status}: {exc.reason}"}), exc.status
    except Exception as exc:
        audit_logger.log(user, "CREATE", name, namespace, "FAILURE", str(exc))
        logger.exception("Unexpected error creating policy %s/%s", namespace, name)
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Policies – delete
# ---------------------------------------------------------------------------

@api_bp.route("/namespaces/<namespace>/policies/<name>", methods=["DELETE"])
@require_auth
def delete_policy(namespace: str, name: str):
    user = get_current_user()

    try:
        custom_objects().delete_namespaced_custom_object(
            group=VARMOR_GROUP,
            version=VARMOR_VERSION,
            namespace=namespace,
            plural=VARMOR_PLURAL,
            name=name,
        )
        audit_logger.log(user, "DELETE", name, namespace, "SUCCESS")
        return jsonify({"message": f"Policy '{name}' deleted successfully"})

    except ApiException as exc:
        audit_logger.log(user, "DELETE", name, namespace, "FAILURE", exc.reason or str(exc.status))
        logger.error("K8s error deleting policy %s/%s: %s", namespace, name, exc)
        return jsonify({"error": f"Kubernetes API error {exc.status}: {exc.reason}"}), exc.status
    except Exception as exc:
        audit_logger.log(user, "DELETE", name, namespace, "FAILURE", str(exc))
        logger.exception("Unexpected error deleting policy %s/%s", namespace, name)
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Deployments – toggle vArmor protection + rollout restart
# ---------------------------------------------------------------------------

@api_bp.route("/namespaces/<namespace>/deployments/<name>/protect", methods=["PUT"])
@require_auth
def set_deployment_protection(namespace: str, name: str):
    user = get_current_user()
    body = request.get_json(silent=True) or {}
    enable = body.get("enable", True)
    label_value = "true" if enable else "false"

    label_patch = {"metadata": {"labels": {"sandbox.varmor.org/enable": label_value}}}
    restart_patch = {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "kubectl.kubernetes.io/restartedAt":
                            datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                    }
                }
            }
        }
    }

    action = "ENABLE_PROTECTION" if enable else "DISABLE_PROTECTION"
    try:
        apps_v1().patch_namespaced_deployment(name=name, namespace=namespace, body=label_patch)
        apps_v1().patch_namespaced_deployment(name=name, namespace=namespace, body=restart_patch)
        audit_logger.log(user, action, name, namespace, "SUCCESS")
        state = "enabled" if enable else "disabled"
        return jsonify({"message": f"Deployment '{name}' protection {state} and restarted"})
    except ApiException as exc:
        audit_logger.log(user, action, name, namespace, "FAILURE", exc.reason or str(exc.status))
        logger.error("K8s error protecting deployment %s/%s: %s", namespace, name, exc)
        return jsonify({"error": f"Kubernetes API error {exc.status}: {exc.reason}"}), exc.status
    except Exception as exc:
        audit_logger.log(user, action, name, namespace, "FAILURE", str(exc))
        logger.exception("Unexpected error protecting deployment %s/%s", namespace, name)
        return jsonify({"error": str(exc)}), 500
