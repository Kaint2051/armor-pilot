import collections
import datetime
import json
import logging
import os
import re

from flask import Blueprint, jsonify, request
from kubernetes.client.rest import ApiException

from ..audit import audit_logger
from ..auth import (
    get_current_user, get_current_role, get_permissions_for_role,
    require_admin, require_auth, require_operator, require_permission,
)
from ..db import (get_queue_item, list_queue, queue_policy,
                  update_queue_status, VALID_ROLES, BUILTIN_ROLES)
from ..k8s_client import (
    VARMOR_GROUP,
    VARMOR_PLURAL,
    VARMOR_VERSION,
    apps_v1,
    core_v1,
    custom_objects,
)
from ..policy_templates import get_policy_templates_payload

logger = logging.getLogger(__name__)
api_bp = Blueprint("api", __name__, url_prefix="/api")

VARMOR_CLUSTER_PLURAL = "varmorclusterpolicies"
ARMOR_PROFILE_MODEL_PLURAL = "armorprofilemodels"
ARMOR_PROFILE_PLURAL = "armorprofiles"

VALID_ENFORCER_COMBOS = frozenset([
    frozenset(["AppArmor"]),
    frozenset(["BPF"]),
    frozenset(["Seccomp"]),
    frozenset(["NetworkProxy"]),
    frozenset(["AppArmor", "BPF"]),
    frozenset(["AppArmor", "Seccomp"]),
    frozenset(["BPF", "Seccomp"]),
    frozenset(["BPF", "NetworkProxy"]),
    frozenset(["AppArmor", "BPF", "Seccomp"]),
    frozenset(["BPF", "NetworkProxy", "Seccomp"]),  # NetworkProxyBPFSeccomp per CRD common.go
])

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
VALID_SCMP_ACTIONS = frozenset(["SCMP_ACT_KILL", "SCMP_ACT_ERRNO", "SCMP_ACT_LOG", "SCMP_ACT_ALLOW"])
VALID_DID_PROFILE_TYPES = frozenset(["BehaviorModel", "Custom"])
VALID_LABEL_SELECTOR_OPERATORS = frozenset(["In", "NotIn", "Exists", "DoesNotExist"])
VALID_QUEUE_STATUSES = frozenset(["pending", "approved", "rejected", "cancelled"])
POLICY_BACKUP_VERSION = "varmor-console-backup/v1"


def _clean_str_list(values) -> list[str]:
    return [str(v).strip() for v in (values or []) if str(v).strip()]


def _normalize_capability_rule(raw: str) -> str:
    cap = str(raw or "").strip().lower()
    if not cap:
        return ""
    if cap.startswith("disable-cap-"):
        cap = cap[len("disable-cap-"):]
    cap = re.sub(r"^cap[_-]", "", cap)
    cap = cap.replace("_", "-")
    if not re.fullmatch(r"[a-z0-9-]+", cap):
        return ""
    return f"disable-cap-{cap}"


def _is_hardening_rule(rule: str) -> bool:
    return rule in HARDENING_RULES or bool(re.fullmatch(r"disable-cap-[a-z0-9-]+", rule or ""))


def _normalize_selector(raw: dict) -> tuple[dict | None, str | None]:
    if not raw:
        return None, None
    if not isinstance(raw, dict):
        return None, "target_selector must be an object"
    selector: dict = {}
    labels = raw.get("matchLabels") or {}
    if labels:
        if not isinstance(labels, dict):
            return None, "target_selector.matchLabels must be an object"
        clean_labels = {str(k).strip(): str(v).strip() for k, v in labels.items() if str(k).strip() and str(v).strip()}
        if clean_labels:
            selector["matchLabels"] = clean_labels

    expressions = raw.get("matchExpressions") or []
    if expressions:
        if not isinstance(expressions, list):
            return None, "target_selector.matchExpressions must be an array"
        clean_exprs = []
        for expr in expressions:
            if not isinstance(expr, dict):
                return None, "Each matchExpression must be an object"
            key = str(expr.get("key") or "").strip()
            op = str(expr.get("operator") or "").strip()
            values = _clean_str_list(expr.get("values") or [])
            if not key or op not in VALID_LABEL_SELECTOR_OPERATORS:
                return None, "Each matchExpression requires key and operator In, NotIn, Exists, or DoesNotExist"
            item = {"key": key, "operator": op}
            if values:
                item["values"] = values
            clean_exprs.append(item)
        if clean_exprs:
            selector["matchExpressions"] = clean_exprs

    return selector or None, None


def _normalize_apparmor_raw_rules(raw_rules, banned_files=None) -> list[dict]:
    result = [{"rules": f"deny {p.strip()} rwmlk,"} for p in (banned_files or []) if str(p).strip()]
    for item in raw_rules or []:
        if isinstance(item, dict):
            rules = str(item.get("rules") or "").strip()
            if not rules:
                continue
            entry = {"rules": rules}
            targets = _clean_str_list(item.get("targets") or [])
            if targets:
                entry["targets"] = targets
            result.append(entry)
        else:
            rules = str(item or "").strip()
            if rules:
                result.append({"rules": rules})
    return result


def _normalize_syscall_raw_rules(raw_rules) -> tuple[list[dict], str | None]:
    normalized = []
    for item in raw_rules or []:
        if not isinstance(item, dict):
            return [], "Each syscall raw rule must be an object"
        names = _clean_str_list(item.get("names") or [])
        action = str(item.get("action") or "").strip()
        if not names or action not in VALID_SCMP_ACTIONS:
            return [], "Each syscall raw rule requires names and a valid Seccomp action"
        entry = {"names": names, "action": action}
        for optional_key in ("args", "errnoRet", "comment", "includes", "excludes"):
            if optional_key in item:
                entry[optional_key] = item[optional_key]
        normalized.append(entry)
    return normalized, None


def _k8s_error_msg(exc) -> str:
    """Extract the most informative error message from a K8s ApiException."""
    try:
        body = json.loads(exc.body) if exc.body else {}
        msg = body.get("message", "")
        if msg:
            return f"Kubernetes API error {exc.status}: {msg}"
    except Exception:
        pass
    return f"Kubernetes API error {exc.status}: {exc.reason}"


def _sanitize_name(raw: str) -> str:
    name = re.sub(r"[_\s]+", "-", raw.strip().lower())
    name = re.sub(r"[^a-z0-9\-]", "", name)
    return name.strip("-")


def _bounded_int_arg(name: str, default: int, maximum: int) -> int:
    try:
        value = int(request.args.get(name, default))
    except (ValueError, TypeError):
        value = default
    return max(1, min(value, maximum))


def _parse_policy_item(item: dict, scope: str = "namespace", ns_fallback: str = "") -> dict:
    meta = item.get("metadata", {})
    spec = item.get("spec", {})
    conditions = item.get("status", {}).get("conditions", [])
    status = "Pending"
    status_reason = ""
    status_message = ""
    for cond in conditions:
        if cond.get("type") == "Ready":
            if cond.get("status") == "True":
                status = "Ready"
            else:
                status = cond.get("reason", "Pending") or "Pending"
                status_message = cond.get("message", "") or ""
            break
    return {
        "name": meta.get("name", ""),
        "namespace": meta.get("namespace", ns_fallback),
        "created_at": meta.get("creationTimestamp", ""),
        "status": status,
        "status_message": status_message,
        "phase": item.get("status", {}).get("phase", ""),
        "mode": spec.get("policy", {}).get("mode", "Unknown"),
        "enforcer": spec.get("policy", {}).get("enforcer", ""),
        "target": spec.get("target", {}),
        "scope": scope,
    }


def _patch_unconfined_annotations(namespace: str, kind: str, name: str, containers: list[str]) -> None:
    """Patch workload annotations for container-level unconfined AppArmor override."""
    if not name or not containers:
        return
    annotations = {
        f"container.apparmor.security.beta.varmor.org/{c}": "unconfined"
        for c in containers
    }
    try:
        if kind == "Pod":
            core_v1().patch_namespaced_pod(
                name=name, namespace=namespace,
                body={"metadata": {"annotations": annotations}},
            )
        else:
            patch = {"spec": {"template": {"metadata": {"annotations": annotations}}}}
            api = apps_v1()
            if kind == "Deployment":
                api.patch_namespaced_deployment(name=name, namespace=namespace, body=patch)
            elif kind == "StatefulSet":
                api.patch_namespaced_stateful_set(name=name, namespace=namespace, body=patch)
            elif kind == "DaemonSet":
                api.patch_namespaced_daemon_set(name=name, namespace=namespace, body=patch)
    except Exception as exc:
        logger.warning("Failed to patch unconfined annotations on %s/%s/%s: %s", kind, namespace, name, exc)


def _build_file_rule(r: dict) -> dict:
    rule: dict = {"pattern": r["pattern"], "permissions": r["permissions"]}
    quals = r.get("qualifiers") or []
    if quals:
        rule["qualifiers"] = quals
    return rule


def _build_enhance_protect(rules, banned_files, bpf_file_rules, bpf_process_rules,
                            bpf_network, bpf_ptrace, bpf_mounts,
                            seccomp_syscalls, seccomp_action, enforcers,
                            audit_violations, allow_violations,
                            attack_protection_groups, network_proxy_egress,
                            apparmor_raw_rules, seccomp_raw_rules,
                            privileged) -> dict:
    hardening = [r for r in rules if _is_hardening_rule(r)]
    attack = [r for r in rules if r in ATTACK_RULES]
    vuln = [r for r in rules if r in VULN_RULES]
    apparmor_raw = _normalize_apparmor_raw_rules(apparmor_raw_rules, banned_files)

    ep: dict = {}
    if hardening:
        ep["hardeningRules"] = hardening
    if attack:
        if attack_protection_groups:
            # Per-rule groups provided; track which rules are covered
            covered = set()
            valid_groups = []
            for g in attack_protection_groups:
                group_rules = [r for r in (g.get("rules") or []) if r in ATTACK_RULES]
                if not group_rules:
                    continue
                entry: dict = {"rules": group_rules}
                targets = _clean_str_list(g.get("targets") or [])
                if targets:
                    entry["targets"] = targets
                valid_groups.append(entry)
                covered.update(group_rules)
            # Remaining attack rules (not in any group) → one default entry
            ungrouped = [r for r in attack if r not in covered]
            if ungrouped:
                valid_groups.append({"rules": ungrouped})
            if valid_groups:
                ep["attackProtectionRules"] = valid_groups
        else:
            ep["attackProtectionRules"] = [{"rules": attack}]
    if vuln:
        ep["vulMitigationRules"] = vuln
    if apparmor_raw:
        ep["appArmorRawRules"] = apparmor_raw
    if audit_violations:
        ep["auditViolations"] = True
    if allow_violations:
        ep["allowViolations"] = True
    if privileged:
        ep["privileged"] = True

    if "BPF" in enforcers:
        bpf_obj: dict = {}
        files = [_build_file_rule(r) for r in bpf_file_rules if r.get("pattern")]
        procs = [_build_file_rule(r) for r in bpf_process_rules if r.get("pattern")]
        if files:
            bpf_obj["files"] = files
        if procs:
            bpf_obj["processes"] = procs
        if bpf_network and isinstance(bpf_network, dict):
            bpf_obj["network"] = bpf_network
        if bpf_ptrace and isinstance(bpf_ptrace, dict):
            bpf_obj["ptrace"] = bpf_ptrace
        mounts = [r for r in (bpf_mounts or []) if r.get("sourcePattern")]
        if mounts:
            bpf_obj["mounts"] = mounts
        if bpf_obj:
            ep["bpfRawRules"] = bpf_obj

    if "Seccomp" in enforcers:
        if seccomp_raw_rules:
            ep["syscallRawRules"] = seccomp_raw_rules
        elif seccomp_syscalls:
            action = seccomp_action if seccomp_action in VALID_SCMP_ACTIONS else "SCMP_ACT_ERRNO"
            ep["syscallRawRules"] = [{"names": seccomp_syscalls, "action": action}]

    if "NetworkProxy" in enforcers and network_proxy_egress and isinstance(network_proxy_egress, dict):
        err = _validate_np_egress(network_proxy_egress)
        if err:
            raise ValueError(f"NetworkProxy egress: {err}")
        ep["networkProxyRawRules"] = {"egress": network_proxy_egress}

    return ep


def _build_defense_in_depth(body: dict) -> dict:
    did: dict = {}

    if body.get("did_allow_violations"):
        did["allowViolations"] = True

    aa_type = (body.get("did_apparmor_type") or "").strip()
    if aa_type in VALID_DID_PROFILE_TYPES:
        aa: dict = {"profileType": aa_type}
        aa_custom = (body.get("did_apparmor_custom") or "").strip()
        if aa_type == "Custom" and aa_custom:
            aa["customProfile"] = aa_custom
        aa_raw = _normalize_apparmor_raw_rules(body.get("did_apparmor_raw_rules") or [])
        if aa_raw:
            aa["appArmorRawRules"] = aa_raw
        did["appArmor"] = aa

    sc_type = (body.get("did_seccomp_type") or "").strip()
    if sc_type in VALID_DID_PROFILE_TYPES:
        sc: dict = {"profileType": sc_type}
        sc_custom = (body.get("did_seccomp_custom") or "").strip()
        if sc_type == "Custom" and sc_custom:
            sc["customProfile"] = sc_custom
        sc_raw_rules = body.get("did_seccomp_raw_rules") or []
        normalized_sc_raw, sc_raw_err = _normalize_syscall_raw_rules(sc_raw_rules)
        if sc_raw_err:
            raise ValueError(sc_raw_err)
        sc_syscalls = _clean_str_list(body.get("did_seccomp_syscalls") or [])
        if normalized_sc_raw:
            sc["syscallRawRules"] = normalized_sc_raw
        elif sc_syscalls:
            action = body.get("did_seccomp_action") or "SCMP_ACT_ERRNO"
            if action not in VALID_SCMP_ACTIONS:
                action = "SCMP_ACT_ERRNO"
            sc["syscallRawRules"] = [{"names": sc_syscalls, "action": action}]
        did["seccomp"] = sc

    np_egress = body.get("did_np_egress")
    if np_egress and isinstance(np_egress, dict):
        err = _validate_np_egress(np_egress)
        if err:
            raise ValueError(f"DefenseInDepth networkProxy.egress: {err}")
        did["networkProxy"] = {"egress": np_egress}

    return did


def _validate_port_obj(p: dict, path: str) -> str | None:
    if not isinstance(p, dict):
        return f"{path} must be an object"
    port = p.get("port")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        return f"{path}.port must be an integer in [1, 65535]"
    end = p.get("endPort")
    if end is not None:
        if not isinstance(end, int) or not (1 <= end <= 65535):
            return f"{path}.endPort must be an integer in [1, 65535]"
        if end < port:
            return f"{path}.endPort ({end}) must be >= port ({port})"
    return None


def _validate_np_egress(egress: dict) -> str | None:
    if not isinstance(egress, dict):
        return "egress must be an object"
    default_action = egress.get("defaultAction", "")
    rules = egress.get("rules") or []
    http_rules = egress.get("httpRules") or []
    # defaultAction is always required when egress object exists (no omitempty in CRD)
    if default_action not in ("allow", "deny"):
        return ("egress.defaultAction is required and must be 'allow' or 'deny' "
                f"(got '{default_action}')")
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            return f"egress.rules[{i}] must be an object"
        # Validate ports first so format errors surface before missing-field errors
        for j, port_obj in enumerate(rule.get("ports") or []):
            err = _validate_port_obj(port_obj, f"egress.rules[{i}].ports[{j}]")
            if err:
                return err
        if not (rule.get("qualifiers") or []):
            return f"egress.rules[{i}].qualifiers is required"
        # ip and cidr are both optional per CRD (port-only rules are valid)
        if rule.get("ip") and rule.get("cidr"):
            return f"egress.rules[{i}]: 'ip' and 'cidr' are mutually exclusive"
    for i, rule in enumerate(http_rules):
        if not isinstance(rule, dict):
            return f"egress.httpRules[{i}] must be an object"
        if not (rule.get("qualifiers") or []):
            return f"egress.httpRules[{i}].qualifiers is required"
        # match is required per CRD (no omitempty on Match field)
        match = rule.get("match")
        if not isinstance(match, dict):
            return f"egress.httpRules[{i}].match is required and must be an object"
        for j, port_obj in enumerate(match.get("ports") or []):
            err = _validate_port_obj(port_obj, f"egress.httpRules[{i}].match.ports[{j}]")
            if err:
                return err
    return None


def _validate_np_header_mutations(mutations: list) -> str | None:
    for i, dm in enumerate(mutations):
        if not isinstance(dm, dict):
            return f"headerMutations[{i}] must be an object"
        if not dm.get("domain"):
            return f"headerMutations[{i}].domain is required"
        for j, h in enumerate(dm.get("headers") or []):
            if not isinstance(h, dict):
                return f"headerMutations[{i}].headers[{j}] must be an object"
            if not h.get("name"):
                return f"headerMutations[{i}].headers[{j}].name is required"
            has_value = "value" in h
            has_secret = "secretRef" in h
            if not has_value and not has_secret:
                return f"headerMutations[{i}].headers[{j}] must have 'value' or 'secretRef'"
            if has_value and has_secret:
                return (f"headerMutations[{i}].headers[{j}]: "
                        "'value' and 'secretRef' are mutually exclusive")
            if has_secret:
                sr = h.get("secretRef")
                if not isinstance(sr, dict) or not sr.get("name") or not sr.get("key"):
                    return (f"headerMutations[{i}].headers[{j}].secretRef "
                            "must have both 'name' and 'key'")
    return None


def _build_network_proxy_config(body: dict) -> dict:
    cfg: dict = {}

    domains = [d.strip() for d in (body.get("np_mitm_domains") or []) if str(d).strip()]
    if domains:
        mitm: dict = {"domains": domains}
        mutations = body.get("np_mitm_mutations")
        if mutations and isinstance(mutations, list):
            err = _validate_np_header_mutations(mutations)
            if err:
                raise ValueError(f"NetworkProxy header mutations: {err}")
            mitm["headerMutations"] = mutations
        cfg["mitm"] = mitm

    for key, field in [("np_proxy_uid", "proxyUID"), ("np_proxy_port", "proxyPort"),
                        ("np_proxy_admin_port", "proxyAdminPort")]:
        val = body.get(key)
        if val is not None:
            try:
                cfg[field] = int(val)
            except (ValueError, TypeError):
                pass

    resources = body.get("np_resources")
    if resources and isinstance(resources, dict):
        clean_resources = {}
        for key in ("requests", "limits"):
            values = resources.get(key)
            if isinstance(values, dict):
                clean_values = {str(k): str(v) for k, v in values.items() if str(k) and str(v)}
                if clean_values:
                    clean_resources[key] = clean_values
        if clean_resources:
            cfg["resources"] = clean_resources

    return cfg


def _build_manifest_from_body(body: dict, scope: str, name: str, namespace: str) -> tuple:
    """Parse request body and build a CRD manifest. Returns (manifest_dict, error_str_or_None)."""
    target_kind = (body.get("target_kind") or "Deployment").strip()
    target_name = (body.get("target_deployment") or "").strip()
    target_selector_raw: dict = body.get("target_selector") or {}
    target_containers: list = [c.strip() for c in body.get("target_containers") or [] if str(c).strip()]
    mode = (body.get("mode") or "EnhanceProtect").strip()
    enforcers: list = body.get("enforcers") or ["AppArmor"]
    rules: list = _clean_str_list(body.get("rules") or [])
    capability_rules = []
    for raw_cap in body.get("capability_rules") or []:
        cap_rule = _normalize_capability_rule(raw_cap)
        if not cap_rule:
            return None, f"Invalid capability rule '{raw_cap}'"
        capability_rules.append(cap_rule)
    rules = list(dict.fromkeys(rules + capability_rules))
    banned_files: list = body.get("banned_files") or []
    apparmor_raw_rules: list = body.get("apparmor_raw_rules") or []
    bpf_file_rules: list = body.get("bpf_file_rules") or []
    bpf_process_rules: list = body.get("bpf_process_rules") or []
    bpf_network = body.get("bpf_network")
    bpf_ptrace = body.get("bpf_ptrace")
    bpf_mounts: list = body.get("bpf_mounts") or []
    seccomp_syscalls: list = _clean_str_list(body.get("seccomp_syscalls") or [])
    seccomp_action: str = body.get("seccomp_action") or "SCMP_ACT_ERRNO"
    seccomp_raw_rules, seccomp_raw_err = _normalize_syscall_raw_rules(body.get("seccomp_raw_rules") or [])
    if seccomp_raw_err:
        return None, seccomp_raw_err
    # Per-rule attack protection groups [{rules:[...], targets:[...]}]
    raw_groups = body.get("attack_protection_groups") or []
    attack_protection_groups: list = raw_groups if isinstance(raw_groups, list) else []
    network_proxy_egress = body.get("np_egress")
    privileged = bool(body.get("privileged", False))
    try:
        modeling_duration: int = int(body.get("modeling_duration") or 3600)
    except (ValueError, TypeError):
        return None, "modeling_duration must be an integer number of seconds"
    if modeling_duration <= 0:
        return None, "modeling_duration must be greater than 0"
    update_existing = bool(body.get("update_existing_workloads", False))
    audit_violations = bool(body.get("audit_violations", False))
    allow_violations = bool(body.get("allow_violations", False))

    if mode not in VALID_MODES:
        return None, f"Invalid mode '{mode}'"
    if target_kind not in VALID_KINDS:
        return None, f"Invalid target_kind '{target_kind}'"
    if mode == "BehaviorModeling" and "NetworkProxy" in enforcers:
        return None, "BehaviorModeling mode is not supported with NetworkProxy enforcer"
    if mode == "DefenseInDepth" and "BPF" in enforcers:
        return None, "DefenseInDepth mode does not support BPF enforcer"
    enf_set = frozenset(enforcers)
    if enf_set not in VALID_ENFORCER_COMBOS:
        valid_strs = ["+".join(sorted(s)) for s in sorted(VALID_ENFORCER_COMBOS, key=len)]
        return None, (
            f"Unsupported enforcer combination '{'+'.join(sorted(enforcers))}'. "
            f"Valid combinations: {', '.join(valid_strs)}"
        )

    target_selector, selector_err = _normalize_selector(target_selector_raw)
    if selector_err:
        return None, selector_err

    if not target_name and not target_selector:
        return None, "Provide 'target_deployment' (name) or 'target_selector' (label selector)"

    target: dict = {"kind": target_kind}
    if target_selector:
        target["selector"] = target_selector
    else:
        target["name"] = target_name
    if target_containers:
        target["containers"] = target_containers

    enforcer_str = "|".join(enforcers) if enforcers else "AppArmor"
    spec_policy: dict = {"enforcer": enforcer_str, "mode": mode}

    if mode == "EnhanceProtect":
        try:
            ep = _build_enhance_protect(
                rules, banned_files, bpf_file_rules, bpf_process_rules,
                bpf_network, bpf_ptrace, bpf_mounts,
                seccomp_syscalls, seccomp_action, enforcers,
                audit_violations, allow_violations, attack_protection_groups,
                network_proxy_egress, apparmor_raw_rules, seccomp_raw_rules,
                privileged,
            )
        except ValueError as exc:
            return None, str(exc)
        if not ep:
            return None, "EnhanceProtect policy must have at least one rule, banned file, or raw rule"
        spec_policy["enhanceProtect"] = ep

        if "NetworkProxy" in enforcers:
            try:
                np_cfg = _build_network_proxy_config(body)
            except ValueError as exc:
                return None, str(exc)
            if np_cfg:
                spec_policy["networkProxyConfig"] = np_cfg

    elif mode == "BehaviorModeling":
        spec_policy["modelingOptions"] = {"duration": modeling_duration}

    elif mode == "DefenseInDepth":
        try:
            did = _build_defense_in_depth(body)
        except ValueError as exc:
            return None, str(exc)
        if not did:
            return None, "DefenseInDepth policy must configure at least one profile or NetworkProxy rule"
        spec_policy["defenseInDepth"] = did

    spec: dict = {
        "updateExistingWorkloads": update_existing,
        "target": target,
        "policy": spec_policy,
    }

    if scope == "cluster":
        manifest = {
            "apiVersion": f"{VARMOR_GROUP}/{VARMOR_VERSION}",
            "kind": "VarmorClusterPolicy",
            "metadata": {"name": name},
            "spec": spec,
        }
    else:
        manifest = {
            "apiVersion": f"{VARMOR_GROUP}/{VARMOR_VERSION}",
            "kind": "VarmorPolicy",
            "metadata": {"name": name, "namespace": namespace},
            "spec": spec,
        }

    return manifest, None


def _utc_backup_timestamp() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _strip_policy_manifest(raw: dict) -> tuple[dict | None, str | None]:
    """Return a portable policy manifest with volatile Kubernetes fields removed."""
    if not isinstance(raw, dict):
        return None, "manifest must be an object"
    kind = raw.get("kind")
    if kind not in ("VarmorPolicy", "VarmorClusterPolicy"):
        return None, "kind must be VarmorPolicy or VarmorClusterPolicy"
    meta = raw.get("metadata") or {}
    spec = raw.get("spec") or {}
    name = str(meta.get("name") or "").strip()
    if not name:
        return None, "metadata.name is required"
    if not isinstance(spec, dict) or not spec:
        return None, "spec is required"

    # Validate enforcer if present — catches garbage before it reaches the cluster.
    policy = spec.get("policy") or {}
    enforcer_str = str(policy.get("enforcer") or "").strip()
    if enforcer_str:
        enf_set = frozenset(e.strip() for e in enforcer_str.split("|") if e.strip())
        if enf_set not in VALID_ENFORCER_COMBOS:
            valid_strs = ", ".join("+".join(sorted(s)) for s in sorted(VALID_ENFORCER_COMBOS, key=len))
            return None, f"invalid enforcer '{enforcer_str}'. Valid: {valid_strs}"

    clean_meta: dict = {"name": name}
    if kind == "VarmorPolicy":
        clean_meta["namespace"] = str(meta.get("namespace") or "default").strip() or "default"
    for key in ("labels", "annotations"):
        value = meta.get(key)
        if isinstance(value, dict) and value:
            clean_meta[key] = value

    return {
        "apiVersion": f"{VARMOR_GROUP}/{VARMOR_VERSION}",
        "kind": kind,
        "metadata": clean_meta,
        "spec": spec,
    }, None


def _backup_manifest_identity(manifest: dict) -> dict:
    meta = manifest.get("metadata") or {}
    spec = manifest.get("spec") or {}
    policy = spec.get("policy") or {}
    scope = "cluster" if manifest.get("kind") == "VarmorClusterPolicy" else "namespace"
    return {
        "kind": manifest.get("kind"),
        "scope": scope,
        "namespace": "" if scope == "cluster" else meta.get("namespace", "default"),
        "name": meta.get("name", ""),
        "mode": policy.get("mode", ""),
        "enforcer": policy.get("enforcer", ""),
    }


def _backup_payload_entries(payload) -> tuple[list[dict], str | None]:
    """Normalize supported backup payload shapes into indexed manifest entries."""
    if isinstance(payload, dict) and "backup" in payload:
        payload = payload.get("backup")
    if isinstance(payload, dict) and "items" in payload:
        raw_items = payload.get("items") or []
    elif isinstance(payload, dict) and payload.get("kind") in ("VarmorPolicy", "VarmorClusterPolicy"):
        raw_items = [payload]
    elif isinstance(payload, list):
        raw_items = payload
    else:
        return [], "backup must be a backup object, a policy manifest, or an array"
    if not isinstance(raw_items, list):
        return [], "backup.items must be an array"

    entries = []
    for index, item in enumerate(raw_items):
        manifest = item.get("manifest") if isinstance(item, dict) and "manifest" in item else item
        clean, err = _strip_policy_manifest(manifest)
        identity = _backup_manifest_identity(clean) if clean else {
            "kind": "",
            "scope": "",
            "namespace": "",
            "name": "",
            "mode": "",
            "enforcer": "",
        }
        entries.append({"index": index, "manifest": clean, "error": err, **identity})
    return entries, None


def _policy_manifest_exists(manifest: dict) -> tuple[bool, str | None]:
    meta = manifest.get("metadata") or {}
    name = meta.get("name")
    try:
        if manifest.get("kind") == "VarmorClusterPolicy":
            custom_objects().get_cluster_custom_object(
                group=VARMOR_GROUP, version=VARMOR_VERSION,
                plural=VARMOR_CLUSTER_PLURAL, name=name,
            )
        else:
            custom_objects().get_namespaced_custom_object(
                group=VARMOR_GROUP, version=VARMOR_VERSION,
                namespace=meta.get("namespace", "default"),
                plural=VARMOR_PLURAL, name=name,
            )
        return True, None
    except ApiException as exc:
        if exc.status == 404:
            return False, None
        return False, _k8s_error_msg(exc)


def _restore_preview_items(entries: list[dict], conflict_action: str) -> list[dict]:
    preview = []
    for entry in entries:
        item = {k: entry.get(k) for k in ("index", "kind", "scope", "namespace", "name", "mode", "enforcer")}
        item["valid"] = not entry.get("error")
        item["error"] = entry.get("error") or ""
        item["exists"] = False
        item["action"] = "error" if entry.get("error") else "create"
        if entry.get("manifest"):
            exists, err = _policy_manifest_exists(entry["manifest"])
            if err:
                item["valid"] = False
                item["error"] = err
                item["action"] = "error"
            else:
                item["exists"] = exists
                item["action"] = "skip" if exists and conflict_action == "skip" else ("overwrite" if exists else "create")
        preview.append(item)
    return preview


def _apply_backup_manifest(manifest: dict, conflict_action: str) -> dict:
    meta = manifest.get("metadata") or {}
    name = meta.get("name")
    namespace = meta.get("namespace", "default")
    exists, err = _policy_manifest_exists(manifest)
    if err:
        return {"name": name, "namespace": namespace, "status": "error", "error": err}
    if exists and conflict_action == "skip":
        return {"name": name, "namespace": namespace, "status": "skipped"}

    try:
        if manifest.get("kind") == "VarmorClusterPolicy":
            if exists:
                custom_objects().patch_cluster_custom_object(
                    group=VARMOR_GROUP, version=VARMOR_VERSION,
                    plural=VARMOR_CLUSTER_PLURAL, name=name, body=manifest,
                )
                status = "overwritten"
            else:
                custom_objects().create_cluster_custom_object(
                    group=VARMOR_GROUP, version=VARMOR_VERSION,
                    plural=VARMOR_CLUSTER_PLURAL, body=manifest,
                )
                status = "created"
            return {"name": name, "namespace": "", "scope": "cluster", "status": status}

        if exists:
            custom_objects().patch_namespaced_custom_object(
                group=VARMOR_GROUP, version=VARMOR_VERSION,
                namespace=namespace, plural=VARMOR_PLURAL, name=name, body=manifest,
            )
            status = "overwritten"
        else:
            custom_objects().create_namespaced_custom_object(
                group=VARMOR_GROUP, version=VARMOR_VERSION,
                namespace=namespace, plural=VARMOR_PLURAL, body=manifest,
            )
            status = "created"
        return {"name": name, "namespace": namespace, "scope": "namespace", "status": status}
    except ApiException as exc:
        return {"name": name, "namespace": namespace, "status": "error", "error": _k8s_error_msg(exc)}
    except Exception as exc:
        return {"name": name, "namespace": namespace, "status": "error", "error": str(exc)}


# ---------------------------------------------------------------------------
# Deployments sidebar
# ---------------------------------------------------------------------------

@api_bp.route("/namespaces/<namespace>/deployments", methods=["GET"])
@require_auth
def list_deployments(namespace: str):
    try:
        result = apps_v1().list_namespaced_deployment(namespace=namespace)
    except ApiException as exc:
        logger.error("K8s error listing deployments in %s: %s", namespace, exc)
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        logger.exception("Unexpected error listing deployments in %s", namespace)
        return jsonify({"error": str(exc)}), 500

    deployments = []
    for dep in result.items:
        meta_labels = dep.metadata.labels or {}
        pod_labels = (
            (dep.spec.template.metadata.labels or {})
            if dep.spec.template and dep.spec.template.metadata else {}
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
# Workloads – list by kind (target dropdown)
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
        elif kind == "Pod":
            items = core_v1().list_namespaced_pod(namespace=namespace).items
        else:
            items = []

        workloads = []
        for item in items:
            meta_labels = item.metadata.labels or {}
            pod_labels = {}
            if (kind != "Pod" and hasattr(item, "spec") and hasattr(item.spec, "template")
                    and item.spec.template and item.spec.template.metadata):
                pod_labels = item.spec.template.metadata.labels or {}
            varmor_on = (
                meta_labels.get("sandbox.varmor.org/enable") == "true"
                or pod_labels.get("sandbox.varmor.org/enable") == "true"
            )
            status = item.status if hasattr(item, "status") else None
            if kind == "Pod":
                ready_cond = next(
                    (c for c in (getattr(status, "conditions", None) or []) if getattr(c, "type", "") == "Ready"),
                    None,
                )
                phase = getattr(status, "phase", "") if status else ""
                ready = 1 if ((ready_cond and getattr(ready_cond, "status", "") == "True") or phase == "Running") else 0
                replicas = 1
            else:
                ready = (getattr(status, "ready_replicas", None)
                         or getattr(status, "number_ready", None) or 0) if status else 0
                replicas = getattr(item.spec, "replicas", None) or 0
            workloads.append({
                "name": item.metadata.name,
                "namespace": item.metadata.namespace,
                "kind": kind,
                "replicas": replicas,
                "ready_replicas": ready,
                "varmor_enabled": varmor_on,
            })
        return jsonify({"workloads": workloads})
    except ApiException as exc:
        logger.error("K8s error listing %s in %s: %s", kind, namespace, exc)
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        logger.exception("Unexpected error listing %s in %s", kind, namespace)
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Namespace Policies – list / get / create / update / delete
# ---------------------------------------------------------------------------

@api_bp.route("/namespaces/<namespace>/policies", methods=["GET"])
@require_auth
def list_policies(namespace: str):
    try:
        raw = custom_objects().list_namespaced_custom_object(
            group=VARMOR_GROUP, version=VARMOR_VERSION,
            namespace=namespace, plural=VARMOR_PLURAL,
        )
    except ApiException as exc:
        logger.error("K8s error listing policies in %s: %s", namespace, exc)
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        logger.exception("Unexpected error listing policies in %s", namespace)
        return jsonify({"error": str(exc)}), 500

    policies = [_parse_policy_item(i, "namespace", namespace) for i in raw.get("items", [])]
    return jsonify({"policies": policies})


@api_bp.route("/namespaces/<namespace>/policies/<name>", methods=["GET"])
@require_auth
def get_policy(namespace: str, name: str):
    try:
        item = custom_objects().get_namespaced_custom_object(
            group=VARMOR_GROUP, version=VARMOR_VERSION,
            namespace=namespace, plural=VARMOR_PLURAL, name=name,
        )
        return jsonify(item)
    except ApiException as exc:
        logger.error("K8s error getting policy %s/%s: %s", namespace, name, exc)
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        logger.exception("Unexpected error getting policy %s/%s", namespace, name)
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/namespaces/<namespace>/policies/<name>", methods=["PUT"])
@require_permission("policies:edit")
def update_policy(namespace: str, name: str):
    user = get_current_user()
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    try:
        existing = custom_objects().get_namespaced_custom_object(
            group=VARMOR_GROUP, version=VARMOR_VERSION,
            namespace=namespace, plural=VARMOR_PLURAL, name=name,
        )
    except ApiException as exc:
        if exc.status == 404:
            return jsonify({"error": f"Policy '{name}' not found"}), 404
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status

    resource_version = existing.get("metadata", {}).get("resourceVersion", "")
    manifest, err = _build_manifest_from_body(body, "namespace", name, namespace)
    if err:
        return jsonify({"error": err}), 400

    manifest["metadata"]["resourceVersion"] = resource_version
    try:
        custom_objects().replace_namespaced_custom_object(
            group=VARMOR_GROUP, version=VARMOR_VERSION,
            namespace=namespace, plural=VARMOR_PLURAL, name=name, body=manifest,
        )
        audit_logger.log(user, "UPDATE", name, namespace, "SUCCESS")
        return jsonify({"message": f"Policy '{name}' updated successfully"})
    except ApiException as exc:
        audit_logger.log(user, "UPDATE", name, namespace, "FAILURE", exc.reason or str(exc.status))
        logger.error("K8s error updating policy %s/%s: %s", namespace, name, exc)
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        audit_logger.log(user, "UPDATE", name, namespace, "FAILURE", str(exc))
        logger.exception("Unexpected error updating policy %s/%s", namespace, name)
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/namespaces/<namespace>/policies/<name>", methods=["DELETE"])
@require_permission("policies:delete")
def delete_policy(namespace: str, name: str):
    user = get_current_user()
    try:
        custom_objects().delete_namespaced_custom_object(
            group=VARMOR_GROUP, version=VARMOR_VERSION,
            namespace=namespace, plural=VARMOR_PLURAL, name=name,
        )
        audit_logger.log(user, "DELETE", name, namespace, "SUCCESS")
        return jsonify({"message": f"Policy '{name}' deleted successfully"})
    except ApiException as exc:
        audit_logger.log(user, "DELETE", name, namespace, "FAILURE", exc.reason or str(exc.status))
        logger.error("K8s error deleting policy %s/%s: %s", namespace, name, exc)
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        audit_logger.log(user, "DELETE", name, namespace, "FAILURE", str(exc))
        logger.exception("Unexpected error deleting policy %s/%s", namespace, name)
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Cluster Policies – list / get / update / delete
# ---------------------------------------------------------------------------

@api_bp.route("/cluster-policies", methods=["GET"])
@require_auth
def list_cluster_policies():
    try:
        raw = custom_objects().list_cluster_custom_object(
            group=VARMOR_GROUP, version=VARMOR_VERSION, plural=VARMOR_CLUSTER_PLURAL,
        )
    except ApiException as exc:
        logger.error("K8s error listing cluster policies: %s", exc)
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        logger.exception("Unexpected error listing cluster policies")
        return jsonify({"error": str(exc)}), 500

    policies = [_parse_policy_item(i, "cluster") for i in raw.get("items", [])]
    return jsonify({"policies": policies})


@api_bp.route("/cluster-policies/<name>", methods=["GET"])
@require_auth
def get_cluster_policy(name: str):
    try:
        item = custom_objects().get_cluster_custom_object(
            group=VARMOR_GROUP, version=VARMOR_VERSION,
            plural=VARMOR_CLUSTER_PLURAL, name=name,
        )
        return jsonify(item)
    except ApiException as exc:
        logger.error("K8s error getting cluster policy %s: %s", name, exc)
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        logger.exception("Unexpected error getting cluster policy %s", name)
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/cluster-policies/<name>", methods=["PUT"])
@require_permission("policies:edit")
def update_cluster_policy(name: str):
    user = get_current_user()
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    try:
        existing = custom_objects().get_cluster_custom_object(
            group=VARMOR_GROUP, version=VARMOR_VERSION,
            plural=VARMOR_CLUSTER_PLURAL, name=name,
        )
    except ApiException as exc:
        if exc.status == 404:
            return jsonify({"error": f"Cluster policy '{name}' not found"}), 404
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status

    resource_version = existing.get("metadata", {}).get("resourceVersion", "")
    manifest, err = _build_manifest_from_body(body, "cluster", name, "")
    if err:
        return jsonify({"error": err}), 400

    manifest["metadata"]["resourceVersion"] = resource_version
    try:
        custom_objects().replace_cluster_custom_object(
            group=VARMOR_GROUP, version=VARMOR_VERSION,
            plural=VARMOR_CLUSTER_PLURAL, name=name, body=manifest,
        )
        audit_logger.log(user, "UPDATE", name, "cluster", "SUCCESS")
        return jsonify({"message": f"Cluster policy '{name}' updated successfully"})
    except ApiException as exc:
        audit_logger.log(user, "UPDATE", name, "cluster", "FAILURE", exc.reason or str(exc.status))
        logger.error("K8s error updating cluster policy %s: %s", name, exc)
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        audit_logger.log(user, "UPDATE", name, "cluster", "FAILURE", str(exc))
        logger.exception("Unexpected error updating cluster policy %s", name)
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/cluster-policies/<name>", methods=["DELETE"])
@require_permission("policies:delete")
def delete_cluster_policy(name: str):
    user = get_current_user()
    try:
        custom_objects().delete_cluster_custom_object(
            group=VARMOR_GROUP, version=VARMOR_VERSION,
            plural=VARMOR_CLUSTER_PLURAL, name=name,
        )
        audit_logger.log(user, "DELETE", name, "cluster", "SUCCESS")
        return jsonify({"message": f"Cluster policy '{name}' deleted successfully"})
    except ApiException as exc:
        audit_logger.log(user, "DELETE", name, "cluster", "FAILURE", exc.reason or str(exc.status))
        logger.error("K8s error deleting cluster policy %s: %s", name, exc)
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        audit_logger.log(user, "DELETE", name, "cluster", "FAILURE", str(exc))
        logger.exception("Unexpected error deleting cluster policy %s", name)
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Policy create (namespace or cluster via scope param)
# ---------------------------------------------------------------------------

@api_bp.route("/policies", methods=["POST"])
@require_permission("policies:apply_direct")
def create_policy():
    user = get_current_user()
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    raw_name = (body.get("name") or "").strip()
    name = _sanitize_name(raw_name)
    namespace = (body.get("namespace") or "default").strip()
    scope = (body.get("scope") or "namespace").strip()

    if not name:
        return jsonify({"error": "Policy name is required and must contain at least one alphanumeric character"}), 400
    if len(name) > 63:
        return jsonify({"error": f"Policy name too long ({len(name)} chars); max 63 after sanitization"}), 400
    if scope not in ("namespace", "cluster"):
        return jsonify({"error": "scope must be 'namespace' or 'cluster'"}), 400

    manifest, err = _build_manifest_from_body(body, scope, name, namespace)
    if err:
        return jsonify({"error": err}), 400

    unconfined_containers: list = _clean_str_list(body.get("unconfined_containers") or [])

    if scope == "cluster":
        try:
            created = custom_objects().create_cluster_custom_object(
                group=VARMOR_GROUP, version=VARMOR_VERSION,
                plural=VARMOR_CLUSTER_PLURAL, body=manifest,
            )
            audit_logger.log(user, "CREATE", name, "cluster", "SUCCESS")
            actual = created.get("metadata", {}).get("name", name)
            return jsonify({"message": f"Cluster policy '{actual}' created", "name": actual}), 201
        except ApiException as exc:
            audit_logger.log(user, "CREATE", name, "cluster", "FAILURE", exc.reason or str(exc.status))
            logger.error("K8s error creating cluster policy %s: %s", name, exc)
            return jsonify({"error": _k8s_error_msg(exc)}), exc.status
        except Exception as exc:
            audit_logger.log(user, "CREATE", name, "cluster", "FAILURE", str(exc))
            logger.exception("Unexpected error creating cluster policy %s", name)
            return jsonify({"error": str(exc)}), 500
    else:
        try:
            created = custom_objects().create_namespaced_custom_object(
                group=VARMOR_GROUP, version=VARMOR_VERSION,
                namespace=namespace, plural=VARMOR_PLURAL, body=manifest,
            )
            audit_logger.log(user, "CREATE", name, namespace, "SUCCESS")
            actual = created.get("metadata", {}).get("name", name)
            msg = f"Policy '{actual}' created successfully"
            if actual != raw_name:
                msg += f" (name sanitized from '{raw_name}')"
            # Apply container unconfined annotations if requested
            if unconfined_containers:
                target_kind = (body.get("target_kind") or "Deployment").strip()
                target_name = (body.get("target_deployment") or "").strip()
                _patch_unconfined_annotations(namespace, target_kind, target_name, unconfined_containers)
            return jsonify({"message": msg, "name": actual}), 201
        except ApiException as exc:
            audit_logger.log(user, "CREATE", name, namespace, "FAILURE", exc.reason or str(exc.status))
            logger.error("K8s error creating policy %s/%s: %s", namespace, name, exc)
            return jsonify({"error": _k8s_error_msg(exc)}), exc.status
        except Exception as exc:
            audit_logger.log(user, "CREATE", name, namespace, "FAILURE", str(exc))
            logger.exception("Unexpected error creating policy %s/%s", namespace, name)
            return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# User management (SQLite-backed)
# ---------------------------------------------------------------------------

@api_bp.route("/me", methods=["GET"])
@require_auth
def get_me():
    username = get_current_user()
    role = get_current_role()
    return jsonify({
        "username": username,
        "role": role,
        "permissions": sorted(get_permissions_for_role(role)),
    })


@api_bp.route("/policy-templates", methods=["GET"])
@require_permission("policies:view")
def list_policy_templates_endpoint():
    return jsonify(get_policy_templates_payload())


@api_bp.route("/users", methods=["GET"])
@require_permission("users:view")
def list_users_endpoint():
    from ..db import list_users
    return jsonify({"users": list_users()})


@api_bp.route("/users", methods=["POST"])
@require_permission("users:create")
def create_user_endpoint():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    role = body.get("role", "viewer")
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    from ..db import get_all_valid_roles
    all_roles = get_all_valid_roles()
    if role not in all_roles:
        return jsonify({"error": f"role must be one of: {', '.join(sorted(all_roles))}"}), 400
    try:
        from ..db import create_user
        create_user(username, password, role)
    except Exception as exc:
        if "UNIQUE" in str(exc):
            return jsonify({"error": f"Username '{username}' already exists"}), 409
        return jsonify({"error": str(exc)}), 500
    audit_logger.log(get_current_user(), "CREATE_USER", username, "system", "SUCCESS", f"role={role}")
    return jsonify({"ok": True}), 201


@api_bp.route("/users/<username>", methods=["DELETE"])
@require_permission("users:delete")
def delete_user_endpoint(username: str):
    if username == get_current_user():
        return jsonify({"error": "Cannot delete your own account"}), 400
    from ..db import delete_user, get_user
    if not get_user(username):
        return jsonify({"error": "User not found"}), 404
    delete_user(username)
    audit_logger.log(get_current_user(), "DELETE_USER", username, "system", "SUCCESS", "")
    return jsonify({"ok": True})


@api_bp.route("/users/<username>/password", methods=["PUT"])
@require_auth
def change_user_password(username: str):
    from ..auth import current_user_has_permission
    current = get_current_user()
    # Own password: any authenticated user; other user's password: needs users:reset_password
    if current != username and not current_user_has_permission("users:reset_password"):
        return jsonify({"error": "Forbidden: permission \"users:reset_password\" required"}), 403
    body = request.get_json(silent=True) or {}
    new_password = body.get("new_password") or ""
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    # Changing own password requires current password verification
    if current == username:
        from ..db import get_user, verify_password
        user = get_user(username)
        cur_pass = body.get("current_password") or ""
        if not cur_pass or not user or not verify_password(cur_pass, user["password_hash"]):
            return jsonify({"error": "Current password is incorrect"}), 403
    from ..db import update_user_password
    update_user_password(username, new_password)
    audit_logger.log(current, "CHANGE_PASSWORD", username, "system", "SUCCESS", "")
    return jsonify({"ok": True, "message": "Password changed successfully"})


@api_bp.route("/users/<username>/role", methods=["PUT"])
@require_permission("users:update_role")
def change_user_role(username: str):
    if username == get_current_user():
        return jsonify({"error": "Cannot change your own role"}), 400
    body = request.get_json(silent=True) or {}
    role = body.get("role")
    from ..db import get_all_valid_roles
    all_roles = get_all_valid_roles()
    if role not in all_roles:
        return jsonify({"error": f"role must be one of: {', '.join(sorted(all_roles))}"}), 400
    from ..db import update_user_role
    update_user_role(username, role)
    audit_logger.log(get_current_user(), "UPDATE_ROLE", username, "system", "SUCCESS", f"role={role}")
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Custom roles CRUD
# ---------------------------------------------------------------------------

@api_bp.route("/roles", methods=["GET"])
@require_auth
def list_roles_endpoint():
    """Return built-in roles (with their permissions) + custom roles."""
    from ..auth import get_permissions_for_role, ALL_PERMISSIONS
    from ..db import list_custom_roles, BUILTIN_ROLES
    import json

    roles = []
    for r in sorted(BUILTIN_ROLES):
        roles.append({
            "name": r,
            "description": {
                "admin":    "Full access — all permissions",
                "operator": "Policy submit + review view",
                "viewer":   "Read-only",
            }.get(r, ""),
            "permissions": sorted(get_permissions_for_role(r)),
            "builtin": True,
            "user_count": None,
        })
    for cr in list_custom_roles():
        roles.append({
            "name": cr["name"],
            "description": cr["description"],
            "permissions": json.loads(cr["permissions"]),
            "builtin": False,
            "created_at": cr["created_at"],
            "created_by": cr["created_by"],
        })
    # Attach user counts
    from ..db import list_users
    users = list_users()
    count_map: dict = {}
    for u in users:
        count_map[u["role"]] = count_map.get(u["role"], 0) + 1
    for r in roles:
        r["user_count"] = count_map.get(r["name"], 0)

    return jsonify({"roles": roles, "all_permissions": sorted(ALL_PERMISSIONS)})


@api_bp.route("/roles", methods=["POST"])
@require_permission("users:view")  # admin-only gate (same as users:view)
def create_role_endpoint():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip().lower().replace(" ", "_")
    description = (body.get("description") or "").strip()
    permissions = body.get("permissions") or []
    if not name:
        return jsonify({"error": "name is required"}), 400
    if not re.match(r'^[a-z][a-z0-9_-]{0,31}$', name):
        return jsonify({"error": "name must be lowercase letters/digits/underscores, 1-32 chars"}), 400
    if name in BUILTIN_ROLES:
        return jsonify({"error": f"'{name}' is a built-in role and cannot be created"}), 409
    from ..auth import ALL_PERMISSIONS
    invalid = [p for p in permissions if p not in ALL_PERMISSIONS]
    if invalid:
        return jsonify({"error": f"Unknown permissions: {', '.join(invalid)}"}), 400
    try:
        from ..db import create_custom_role
        create_custom_role(name, description, permissions, get_current_user())
    except Exception as exc:
        if "UNIQUE" in str(exc):
            return jsonify({"error": f"Role '{name}' already exists"}), 409
        return jsonify({"error": str(exc)}), 500
    audit_logger.log(get_current_user(), "CREATE_ROLE", name, "system", "SUCCESS",
                     f"perms={len(permissions)}")
    return jsonify({"ok": True}), 201


@api_bp.route("/roles/<name>", methods=["PUT"])
@require_permission("users:view")
def update_role_endpoint(name: str):
    if name in BUILTIN_ROLES:
        return jsonify({"error": "Cannot modify built-in roles"}), 400
    body = request.get_json(silent=True) or {}
    description = (body.get("description") or "").strip()
    permissions = body.get("permissions") or []
    from ..auth import ALL_PERMISSIONS
    invalid = [p for p in permissions if p not in ALL_PERMISSIONS]
    if invalid:
        return jsonify({"error": f"Unknown permissions: {', '.join(invalid)}"}), 400
    from ..db import get_custom_role, update_custom_role
    if not get_custom_role(name):
        return jsonify({"error": "Role not found"}), 404
    update_custom_role(name, description, permissions)
    audit_logger.log(get_current_user(), "UPDATE_ROLE_DEF", name, "system", "SUCCESS",
                     f"perms={len(permissions)}")
    return jsonify({"ok": True})


@api_bp.route("/roles/<name>", methods=["DELETE"])
@require_permission("users:delete")
def delete_role_endpoint(name: str):
    if name in BUILTIN_ROLES:
        return jsonify({"error": "Cannot delete built-in roles"}), 400
    from ..db import get_custom_role, delete_custom_role
    if not get_custom_role(name):
        return jsonify({"error": "Role not found"}), 404
    delete_custom_role(name)
    audit_logger.log(get_current_user(), "DELETE_ROLE", name, "system", "SUCCESS",
                     "affected users demoted to viewer")
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Audit log viewer
# ---------------------------------------------------------------------------

@api_bp.route("/audit-logs", methods=["GET"])
@require_permission("logs:audit")
def get_audit_logs():
    limit = _bounded_int_arg("limit", 100, 500)
    return jsonify({"events": audit_logger.get_events()[:limit]})


# ---------------------------------------------------------------------------
# AppArmor kernel events – read from kern.log
# ---------------------------------------------------------------------------

@api_bp.route("/apparmor-events", methods=["GET"])
@require_permission("logs:apparmor")
def get_apparmor_events():
    log_path = os.environ.get("APPARMOR_LOG_PATH", "/var/log/kern.log")
    limit = _bounded_int_arg("limit", 200, 1000)
    warn = None
    try:
        with open(log_path, "r", errors="replace") as f:
            all_lines = f.readlines()
    except FileNotFoundError:
        return jsonify({
            "events": [],
            "warn": (
                f"Log file not found: {log_path}. "
                "Mount the host kern.log via a hostPath volume in the console deployment, "
                "or set the APPARMOR_LOG_PATH env var."
            ),
        })
    except PermissionError:
        return jsonify({"events": [], "warn": f"Permission denied reading {log_path}."}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    aa_lines = [
        ln.rstrip() for ln in reversed(all_lines)
        if "apparmor=" in ln.lower()
    ][:limit]

    if not aa_lines:
        warn = f"No AppArmor events found in {log_path}."

    return jsonify({"events": aa_lines, "log_path": log_path, **({"warn": warn} if warn else {})})


# ---------------------------------------------------------------------------
# ArmorProfileModel – list / get
# ---------------------------------------------------------------------------

@api_bp.route("/namespaces/<namespace>/profile-models", methods=["GET"])
@require_permission("models:view")
def list_profile_models(namespace: str):
    try:
        raw = custom_objects().list_namespaced_custom_object(
            group=VARMOR_GROUP, version=VARMOR_VERSION,
            namespace=namespace, plural=ARMOR_PROFILE_MODEL_PLURAL,
        )
    except ApiException as exc:
        logger.error("K8s error listing profile models in %s: %s", namespace, exc)
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        logger.exception("Unexpected error listing profile models in %s", namespace)
        return jsonify({"error": str(exc)}), 500

    models = []
    for item in raw.get("items", []):
        meta = item.get("metadata", {})
        status_obj = item.get("status", {})
        conditions = status_obj.get("conditions", [])
        phase = "Unknown"
        for cond in conditions:
            if cond.get("type") == "Completed" and cond.get("status") == "True":
                phase = "Completed"
                break
            if cond.get("type") == "Ready" and cond.get("status") == "True":
                phase = "Ready"
                break
        if phase == "Unknown" and status_obj.get("phase"):
            phase = status_obj["phase"]
        # Fallback: vArmor uses completedNumber/desiredNumber/ready instead of conditions
        if phase == "Unknown":
            desired = status_obj.get("desiredNumber", 0)
            completed = status_obj.get("completedNumber", 0)
            if status_obj.get("ready") and desired > 0 and completed >= desired:
                phase = "Completed"
            elif completed and completed > 0:
                phase = "Modeling"
        models.append({
            "name": meta.get("name", ""),
            "namespace": meta.get("namespace", namespace),
            "created_at": meta.get("creationTimestamp", ""),
            "phase": phase,
            "storage_type": item.get("storageType", ""),
            "desired": status_obj.get("desiredNumber", 0),
            "completed": status_obj.get("completedNumber", 0),
            "ready": bool(status_obj.get("ready", False)),
        })
    return jsonify({"models": models})


@api_bp.route("/namespaces/<namespace>/profile-models/<name>", methods=["GET"])
@require_permission("models:view")
def get_profile_model(namespace: str, name: str):
    try:
        item = custom_objects().get_namespaced_custom_object(
            group=VARMOR_GROUP, version=VARMOR_VERSION,
            namespace=namespace, plural=ARMOR_PROFILE_MODEL_PLURAL, name=name,
        )
        return jsonify(item)
    except ApiException as exc:
        logger.error("K8s error getting profile model %s/%s: %s", namespace, name, exc)
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        logger.exception("Unexpected error getting profile model %s/%s", namespace, name)
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Deployments – toggle protection + rollout restart
# ---------------------------------------------------------------------------

@api_bp.route("/namespaces/<namespace>/deployments/<name>/protect", methods=["PUT"])
@require_admin
def set_deployment_protection(namespace: str, name: str):
    user = get_current_user()
    body = request.get_json(silent=True) or {}
    enable = body.get("enable", True)
    label_patch = {"metadata": {"labels": {"sandbox.varmor.org/enable": "true" if enable else "false"}}}
    restart_patch = {
        "spec": {"template": {"metadata": {"annotations": {
            "kubectl.kubernetes.io/restartedAt": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        }}}}
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
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        audit_logger.log(user, action, name, namespace, "FAILURE", str(exc))
        logger.exception("Unexpected error protecting deployment %s/%s", namespace, name)
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Agent Health — per-node varmor-agent pod status
# ---------------------------------------------------------------------------

def _collect_agent_health() -> dict:
    pods = core_v1().list_namespaced_pod(
        namespace="varmor",
        label_selector="app.kubernetes.io/component=varmor-agent",
    )
    if not pods.items:
        pods = core_v1().list_namespaced_pod(namespace="varmor")
        pods.items = [p for p in pods.items if "agent" in (p.metadata.name or "")]

    agents = []
    for pod in pods.items:
        cs = pod.status.container_statuses or []
        ready = all(c.ready for c in cs) if cs else pod.status.phase == "Running"
        restarts = sum(c.restart_count for c in cs)
        started_at = pod.status.start_time.isoformat() if pod.status.start_time else None
        agents.append({
            "name": pod.metadata.name,
            "node": pod.spec.node_name or "unknown",
            "phase": pod.status.phase or "Unknown",
            "ready": ready,
            "restarts": restarts,
            "started_at": started_at,
        })

    healthy = sum(1 for a in agents if a["ready"])
    return {
        "agents": agents,
        "total": len(agents),
        "healthy": healthy,
        "unhealthy": len(agents) - healthy,
        "restarts": sum(a["restarts"] for a in agents),
    }


@api_bp.route("/agent-health", methods=["GET"])
@require_permission("dashboard:view")
def agent_health():
    try:
        return jsonify(_collect_agent_health())
    except ApiException as exc:
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        logger.exception("Unexpected error fetching agent health")
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Enforcement Events — Seccomp blocks + AppArmor denies from kern.log
# ---------------------------------------------------------------------------

_SYSCALL_NAMES: dict[int, str] = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat",
    9: "mmap", 11: "munmap", 21: "access", 39: "getpid", 56: "clone",
    59: "execve", 60: "exit", 62: "kill", 87: "unlink", 101: "ptrace",
    105: "setuid", 113: "setreuid", 117: "setresuid", 132: "utime",
    154: "sched_setscheduler", 157: "prctl", 165: "mount", 166: "umount2",
    172: "iopl", 173: "ioperm", 175: "init_module", 176: "delete_module",
    186: "gettid", 213: "epoll_create", 246: "kexec_load", 261: "timer_create",
    268: "tgkill", 269: "faccessat", 272: "unshare", 273: "set_robust_list",
    279: "move_pages", 281: "epoll_pwait", 286: "inotify_init1",
    293: "pipe2", 298: "perf_event_open", 302: "prlimit64",
    305: "clock_adjtime", 310: "process_vm_readv", 311: "process_vm_writev",
    313: "finit_module", 317: "seccomp", 318: "getrandom",
    322: "execveat", 332: "statx",
}


def _parse_seccomp_line(line: str) -> dict | None:
    fields: dict[str, str] = {}
    for m in re.finditer(r'(\w+)=("([^"]*)"|\S+)', line):
        key = m.group(1)
        fields[key] = m.group(3) if m.group(3) is not None else m.group(2)

    if "syscall" not in fields:
        return None

    try:
        nr = int(fields["syscall"])
    except ValueError:
        return None

    syscall_name = _SYSCALL_NAMES.get(nr, f"nr={nr}")

    code_raw = fields.get("code", "")
    try:
        code_int = int(code_raw, 16)
        if (code_int & 0xFFFF0000) == 0x00050000:
            action = "SCMP_ACT_ERRNO"       # blocked
        elif code_int == 0x7FFC0000:
            action = "SCMP_ACT_LOG"         # allowed + logged (BehaviorModeling)
        elif code_int == 0x7FFF0000:
            action = "SCMP_ACT_ALLOW"       # allowed silently
        elif code_int == 0x7FF00000:
            action = "SCMP_ACT_TRACE"
        elif code_int == 0x80000000:
            action = "SCMP_ACT_KILL"
        elif code_int == 0:
            action = "SCMP_ACT_KILL_THREAD"
        else:
            action = f"code={code_raw}"
    except (ValueError, TypeError):
        action = code_raw or "unknown"

    ts_m = re.search(r'audit\((\d+\.\d+)', line)
    ts = None
    if ts_m:
        try:
            ts = datetime.datetime.fromtimestamp(float(ts_m.group(1))).isoformat()
        except Exception:
            pass

    return {
        "type": "seccomp",
        "ts": ts,
        "comm": fields.get("comm", ""),
        "pid": fields.get("pid", ""),
        "syscall": syscall_name,
        "syscall_nr": nr,
        "action": action,
    }


def _parse_apparmor_line(line: str) -> dict | None:
    fields: dict[str, str] = {}
    for m in re.finditer(r'(\w+)=("([^"]*)"|\S+)', line):
        key = m.group(1)
        fields[key] = m.group(3) if m.group(3) is not None else m.group(2)

    ts_m = re.search(r'audit\((\d+\.\d+)', line)
    ts = None
    if ts_m:
        try:
            ts = datetime.datetime.fromtimestamp(float(ts_m.group(1))).isoformat()
        except Exception:
            pass

    return {
        "type": "apparmor",
        "ts": ts,
        "profile": fields.get("profile", ""),
        "comm": fields.get("comm", ""),
        "name": fields.get("name", ""),
        "operation": fields.get("operation", ""),
        "action": (fields.get("apparmor") or "DENIED").upper(),
    }


@api_bp.route("/enforcement-events", methods=["GET"])
@require_permission("dashboard:view")
def get_enforcement_events():
    kern_path = os.environ.get("APPARMOR_LOG_PATH", "/var/log/kern.log")
    limit = _bounded_int_arg("limit", 200, 1000)
    enforcer_filter = request.args.get("enforcer", "all")
    warns: list[str] = []
    events: list[dict] = []

    # ── kern.log: AppArmor + Seccomp ──
    if enforcer_filter in ("all", "apparmor", "seccomp"):
        try:
            with open(kern_path, "r", errors="replace") as f:
                kern_lines = f.readlines()
            for raw in reversed(kern_lines):
                if len(events) >= limit:
                    break
                line = raw.rstrip()
                if "type=1326" in line or ("SECCOMP" in line and "syscall=" in line):
                    if enforcer_filter in ("all", "seccomp"):
                        evt = _parse_seccomp_line(line)
                        if evt:
                            events.append(evt)
                elif "apparmor=" in line.lower():
                    if enforcer_filter in ("all", "apparmor"):
                        evt = _parse_apparmor_line(line)
                        if evt:
                            events.append(evt)
        except FileNotFoundError:
            warns.append(f"kern.log not found: {kern_path}")
        except PermissionError:
            warns.append(f"Permission denied: {kern_path}")

    # ── violations.log: BPF events ──
    if enforcer_filter in ("all", "bpf"):
        try:
            with open(_VIOL_LOG_PATH, "r", errors="replace") as f:
                viol_lines = f.readlines()
            for raw in reversed(viol_lines):
                if len(events) >= limit:
                    break
                parsed = _parse_violation_line(raw.rstrip())
                if not parsed or (parsed.get("enforcer") or "").lower() != "bpf":
                    continue
                events.append({
                    "type": "bpf",
                    "ts": parsed.get("ts", ""),
                    "action": parsed.get("action", ""),
                    "operation": parsed.get("operation", ""),
                    "name": parsed.get("path", "") or parsed.get("name", ""),
                    "comm": parsed.get("comm", ""),
                    "capability": parsed.get("capability", ""),
                    "ip": parsed.get("ip", ""),
                    "port": parsed.get("port", ""),
                    "pod": parsed.get("pod", ""),
                    "namespace": parsed.get("namespace", ""),
                    "profile": parsed.get("profile", ""),
                })
        except FileNotFoundError:
            warns.append(f"violations.log not found: {_VIOL_LOG_PATH}")
        except PermissionError:
            warns.append(f"Permission denied: {_VIOL_LOG_PATH}")

    # Sort merged list by ts descending, cap at limit
    events.sort(key=lambda e: e.get("ts", ""), reverse=True)
    events = events[:limit]
    return jsonify({
        "events": events,
        "total": len(events),
        "warn": " | ".join(warns) if warns else None,
    })


def _policy_dashboard_summary(namespace: str) -> dict:
    ns_raw = custom_objects().list_namespaced_custom_object(
        group=VARMOR_GROUP, version=VARMOR_VERSION,
        namespace=namespace, plural=VARMOR_PLURAL,
    )
    cluster_raw = custom_objects().list_cluster_custom_object(
        group=VARMOR_GROUP, version=VARMOR_VERSION, plural=VARMOR_CLUSTER_PLURAL,
    )
    ns_policies = [_parse_policy_item(i, "namespace", namespace) for i in ns_raw.get("items", [])]
    cluster_policies = [_parse_policy_item(i, "cluster") for i in cluster_raw.get("items", [])]
    all_policies = ns_policies + cluster_policies
    by_mode = collections.Counter(p.get("mode") or "Unknown" for p in all_policies)
    by_enforcer: collections.Counter[str] = collections.Counter()
    for policy in all_policies:
        for enforcer in (policy.get("enforcer") or "AppArmor").split("|"):
            if enforcer:
                by_enforcer[enforcer] += 1
    ready = sum(1 for p in all_policies if p.get("status") == "Ready")
    return {
        "namespace": len(ns_policies),
        "cluster": len(cluster_policies),
        "total": len(all_policies),
        "ready": ready,
        "not_ready": len(all_policies) - ready,
        "by_mode": dict(by_mode),
        "by_enforcer": dict(by_enforcer),
        "not_ready_items": [p for p in all_policies if p.get("status") != "Ready"][:8],
    }


def _workload_labels(item, kind: str) -> tuple[dict, dict]:
    meta_labels = item.metadata.labels or {}
    pod_labels = {}
    if kind != "Pod" and getattr(item, "spec", None) and getattr(item.spec, "template", None):
        if item.spec.template and item.spec.template.metadata:
            pod_labels = item.spec.template.metadata.labels or {}
    return meta_labels, pod_labels


def _workload_ready_counts(item, kind: str) -> tuple[int, int, bool]:
    status = getattr(item, "status", None)
    if kind == "DaemonSet":
        desired = getattr(status, "desired_number_scheduled", 0) or 0
        ready = getattr(status, "number_ready", 0) or 0
    elif kind == "Pod":
        desired = 1
        ready_cond = next(
            (c for c in (getattr(status, "conditions", None) or []) if getattr(c, "type", "") == "Ready"),
            None,
        )
        phase = getattr(status, "phase", "") if status else ""
        ready = 1 if ready_cond and getattr(ready_cond, "status", "") == "True" and phase == "Running" else 0
    else:
        desired = getattr(item.spec, "replicas", None) or 0
        ready = getattr(status, "ready_replicas", None) or 0
    return desired, ready, desired > 0 and ready >= desired


def _is_standalone_pod(pod) -> bool:
    """True when the pod has no controller owner (not managed by Deployment/RS/DS/SS)."""
    refs = getattr(pod.metadata, "owner_references", None) or []
    return len(refs) == 0


def _workload_dashboard_summary(namespace: str) -> dict:
    api = apps_v1()
    all_pods = core_v1().list_namespaced_pod(namespace=namespace).items
    sources = {
        "Deployment": api.list_namespaced_deployment(namespace=namespace).items,
        "StatefulSet": api.list_namespaced_stateful_set(namespace=namespace).items,
        "DaemonSet": api.list_namespaced_daemon_set(namespace=namespace).items,
        # Only standalone pods — controller-owned pods are already counted via their owner
        "Pod": [p for p in all_pods if _is_standalone_pod(p)],
    }
    by_kind = {}
    total = ready_workloads = protected = desired_total = ready_total = 0
    not_ready_items = []
    for kind, items in sources.items():
        stats = {"total": len(items), "ready": 0, "protected": 0, "desired": 0, "ready_replicas": 0}
        for item in items:
            desired, ready, is_ready = _workload_ready_counts(item, kind)
            meta_labels, pod_labels = _workload_labels(item, kind)
            is_protected = (
                meta_labels.get("sandbox.varmor.org/enable") == "true"
                or pod_labels.get("sandbox.varmor.org/enable") == "true"
            )
            stats["desired"] += desired
            stats["ready_replicas"] += ready
            if is_ready:
                stats["ready"] += 1
            else:
                not_ready_items.append({
                    "kind": kind,
                    "name": item.metadata.name,
                    "ready": ready,
                    "desired": desired,
                })
            if is_protected:
                stats["protected"] += 1
        by_kind[kind] = stats
        total += stats["total"]
        ready_workloads += stats["ready"]
        protected += stats["protected"]
        desired_total += stats["desired"]
        ready_total += stats["ready_replicas"]
    return {
        "total": total,
        "ready": ready_workloads,
        "not_ready": total - ready_workloads,
        "protected": protected,
        "desired_replicas": desired_total,
        "ready_replicas": ready_total,
        "by_kind": by_kind,
        "not_ready_items": not_ready_items[:8],
    }


def _profile_model_phase(item: dict) -> str:
    status_obj = item.get("status", {})
    for cond in status_obj.get("conditions", []):
        if cond.get("type") == "Completed" and cond.get("status") == "True":
            return "Completed"
        if cond.get("type") == "Ready" and cond.get("status") == "True":
            return "Ready"
    if status_obj.get("phase"):
        return status_obj["phase"]
    desired = status_obj.get("desiredNumber", 0)
    completed = status_obj.get("completedNumber", 0)
    if status_obj.get("ready") and desired > 0 and completed >= desired:
        return "Completed"
    if completed and completed > 0:
        return "Modeling"
    return "Unknown"


def _model_dashboard_summary(namespace: str) -> dict:
    raw = custom_objects().list_namespaced_custom_object(
        group=VARMOR_GROUP, version=VARMOR_VERSION,
        namespace=namespace, plural=ARMOR_PROFILE_MODEL_PLURAL,
    )
    by_phase = collections.Counter()
    by_storage = collections.Counter()
    total = 0
    for item in raw.get("items", []):
        total += 1
        by_phase[_profile_model_phase(item)] += 1
        by_storage[item.get("storageType") or "Unknown"] += 1
    return {"total": total, "by_phase": dict(by_phase), "by_storage": dict(by_storage)}


def _enforcement_dashboard_summary() -> dict:
    result = {
        "total": 0,
        "apparmor": 0,
        "bpf": 0,
        "seccomp": 0,
        "blocked": 0,
        "logged": 0,
        "warn": None,
    }
    warns: list[str] = []

    # ── kern.log: AppArmor + Seccomp kernel events ──
    kern_path = os.environ.get("APPARMOR_LOG_PATH", "/var/log/kern.log")
    try:
        with open(kern_path, "r", errors="replace") as f:
            for raw in collections.deque(f, maxlen=3000):
                line = raw.rstrip()
                if "type=1326" in line or ("SECCOMP" in line and "syscall=" in line):
                    evt = _parse_seccomp_line(line)
                    if not evt:
                        continue
                    result["total"] += 1
                    result["seccomp"] += 1
                    if evt.get("action") in ("SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_KILL_THREAD"):
                        result["blocked"] += 1
                    elif evt.get("action") == "SCMP_ACT_LOG":
                        result["logged"] += 1
                elif "apparmor=" in line.lower():
                    evt = _parse_apparmor_line(line)
                    if not evt:
                        continue
                    result["total"] += 1
                    result["apparmor"] += 1
                    if evt.get("action") in ("DENIED", "AUDIT"):
                        result["blocked"] += 1
    except FileNotFoundError:
        warns.append(f"kern.log not found: {kern_path}")
    except PermissionError:
        warns.append(f"Permission denied: {kern_path}")

    # ── violations.log: BPF events (only source for BPF enforcer) ──
    try:
        with open(_VIOL_LOG_PATH, "r", errors="replace") as f:
            for raw in collections.deque(f, maxlen=3000):
                evt = _parse_violation_line(raw.rstrip())
                if not evt:
                    continue
                if (evt.get("enforcer") or "").lower() != "bpf":
                    continue  # AppArmor/Seccomp already counted from kern.log
                result["total"] += 1
                result["bpf"] += 1
                if evt.get("action") == "DENIED":
                    result["blocked"] += 1
                elif evt.get("action") in ("AUDIT", "AUDIT|ALLOWED"):
                    result["logged"] += 1
    except FileNotFoundError:
        warns.append(f"violations.log not found: {_VIOL_LOG_PATH}")
    except PermissionError:
        warns.append(f"Permission denied: {_VIOL_LOG_PATH}")

    if warns:
        result["warn"] = " | ".join(warns)
    return result


@api_bp.route("/dashboard-summary", methods=["GET"])
@require_permission("dashboard:view")
def dashboard_summary():
    namespace = (request.args.get("namespace") or "default").strip() or "default"
    errors = []

    def collect(name: str, fallback, fn):
        try:
            return fn()
        except ApiException as exc:
            errors.append({"section": name, "error": _k8s_error_msg(exc)})
        except Exception as exc:
            logger.exception("Dashboard section %s failed", name)
            errors.append({"section": name, "error": str(exc)})
        return fallback

    return jsonify({
        "namespace": namespace,
        "policies": collect("policies", {}, lambda: _policy_dashboard_summary(namespace)),
        "workloads": collect("workloads", {}, lambda: _workload_dashboard_summary(namespace)),
        "models": collect("models", {}, lambda: _model_dashboard_summary(namespace)),
        "agents": collect("agents", {}, _collect_agent_health),
        "enforcement": collect("enforcement", {}, _enforcement_dashboard_summary),
        "activity": audit_logger.get_events()[:10],
        "errors": errors,
        "generated_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    })


# ---------------------------------------------------------------------------
# Apply Model as Policy - transition BehaviorModeling policy to DefenseInDepth
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Policy Validate / Submit for Review / Review Queue
# ---------------------------------------------------------------------------

@api_bp.route("/policies/validate", methods=["POST"])
@require_auth
def validate_policy_endpoint():
    """Dry-run: build and validate manifest without writing to cluster."""
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"ok": False, "error": "Request body must be valid JSON"}), 400
    raw_name = (body.get("name") or "").strip()
    name = _sanitize_name(raw_name)
    namespace = (body.get("namespace") or "default").strip()
    scope = (body.get("scope") or "namespace").strip()
    if not name:
        return jsonify({"ok": False, "error": "Policy name is required"}), 400
    if scope not in ("namespace", "cluster"):
        return jsonify({"ok": False, "error": "scope must be 'namespace' or 'cluster'"}), 400
    manifest, err = _build_manifest_from_body(body, scope, name, namespace)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    return jsonify({"ok": True, "manifest": manifest})


@api_bp.route("/policies/submit", methods=["POST"])
@require_operator
def submit_policy_for_review():
    """Validate + save to review queue (does NOT apply to cluster)."""
    user = get_current_user()
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be valid JSON"}), 400
    raw_name = (body.get("name") or "").strip()
    name = _sanitize_name(raw_name)
    namespace = (body.get("namespace") or "default").strip()
    scope = (body.get("scope") or "namespace").strip()
    if not name:
        return jsonify({"error": "Policy name is required"}), 400
    if scope not in ("namespace", "cluster"):
        return jsonify({"error": "scope must be 'namespace' or 'cluster'"}), 400
    _, err = _build_manifest_from_body(body, scope, name, namespace)
    if err:
        return jsonify({"error": err}), 400
    import json as _json
    # Store the original form body (not the built manifest) so the queue detail
    # view can reconstruct field values correctly and unconfined_containers is preserved.
    item_id = queue_policy(name, namespace, scope, _json.dumps(body), user)
    audit_logger.log(user, "SUBMIT_REVIEW", name, namespace, "SUCCESS", f"queue_id={item_id}")
    return jsonify({"ok": True, "id": item_id,
                    "message": f"Policy '{name}' submitted for review"}), 201


@api_bp.route("/policies/queue", methods=["GET"])
@require_permission("review:view")
def list_policy_queue():
    user = get_current_user()
    status_filter = request.args.get("status") or None
    if status_filter and status_filter not in VALID_QUEUE_STATUSES:
        return jsonify({"error": f"status must be one of {sorted(VALID_QUEUE_STATUSES)}"}), 400
    # Approvers see all submissions; others see only their own
    from ..auth import current_user_has_permission
    submitted_by = None if current_user_has_permission("review:approve") else user
    items = list_queue(status=status_filter, submitted_by=submitted_by)
    # Always return total_pending from full (unfiltered) queue so badge is accurate
    pending_items = list_queue(status="pending", submitted_by=submitted_by)
    return jsonify({"queue": items, "total": len(items), "total_pending": len(pending_items)})


@api_bp.route("/policies/queue/<item_id>", methods=["GET"])
@require_permission("review:view")
def get_queue_item_endpoint(item_id: str):
    user = get_current_user()
    item = get_queue_item(item_id)
    if not item:
        return jsonify({"error": "Not found"}), 404
    from ..auth import current_user_has_permission
    if not current_user_has_permission("review:approve") and item["submitted_by"] != user:
        return jsonify({"error": "Forbidden"}), 403
    return jsonify(item)


@api_bp.route("/policies/queue/<item_id>/approve", methods=["POST"])
@require_permission("review:approve")
def approve_queued_policy(item_id: str):
    user = get_current_user()
    body = request.get_json(silent=True) or {}
    item = get_queue_item(item_id)
    if not item:
        return jsonify({"error": "Queue item not found"}), 404
    if item["status"] != "pending":
        return jsonify({"error": f"Cannot approve: item status is '{item['status']}'"}), 400
    import json as _json
    stored = _json.loads(item["manifest"])
    name = item["name"]
    namespace = item["namespace"]
    scope = item["scope"]
    note = (body.get("note") or "").strip()
    # Detect storage format: old entries stored the K8s manifest directly;
    # new entries store the original form body so we can rebuild + get unconfined info.
    if "apiVersion" in stored:
        manifest = stored
        unconfined_containers: list = []
    else:
        manifest, _merr = _build_manifest_from_body(stored, scope, name, namespace)
        if _merr:
            return jsonify({"error": f"Cannot rebuild policy manifest: {_merr}"}), 400
        unconfined_containers = _clean_str_list(stored.get("unconfined_containers") or [])
    def _do_apply():
        """Create policy; if it already exists, patch-update it instead."""
        if scope == "cluster":
            try:
                custom_objects().create_cluster_custom_object(
                    group=VARMOR_GROUP, version=VARMOR_VERSION,
                    plural=VARMOR_CLUSTER_PLURAL, body=manifest,
                )
            except ApiException as exc:
                if exc.status != 409:
                    raise
                custom_objects().patch_cluster_custom_object(
                    group=VARMOR_GROUP, version=VARMOR_VERSION,
                    plural=VARMOR_CLUSTER_PLURAL, name=name, body=manifest,
                )
        else:
            try:
                custom_objects().create_namespaced_custom_object(
                    group=VARMOR_GROUP, version=VARMOR_VERSION,
                    namespace=namespace, plural=VARMOR_PLURAL, body=manifest,
                )
            except ApiException as exc:
                if exc.status != 409:
                    raise
                custom_objects().patch_namespaced_custom_object(
                    group=VARMOR_GROUP, version=VARMOR_VERSION,
                    namespace=namespace, plural=VARMOR_PLURAL,
                    name=name, body=manifest,
                )

    try:
        _do_apply()
        if unconfined_containers and scope != "cluster":
            _tgt = manifest.get("spec", {}).get("target", {})
            _patch_unconfined_annotations(namespace, _tgt.get("kind", ""), _tgt.get("name", ""), unconfined_containers)
        update_queue_status(item_id, "approved", reviewed_by=user, review_note=note or "Approved")
        audit_logger.log(user, "APPROVE_POLICY", name, namespace, "SUCCESS",
                         f"queue_id={item_id}, submitter={item['submitted_by']}")
        return jsonify({"ok": True,
                        "message": f"Policy '{name}' approved and applied to cluster"})
    except ApiException as exc:
        err_msg = _k8s_error_msg(exc)
        update_queue_status(item_id, "rejected", reviewed_by=user,
                            review_note=f"Apply failed: {err_msg}")
        audit_logger.log(user, "APPROVE_POLICY", name, namespace, "FAILURE", err_msg)
        return jsonify({"error": err_msg}), exc.status
    except Exception as exc:
        logger.exception("Unexpected error approving queued policy %s", item_id)
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/policies/queue/<item_id>/reject", methods=["POST"])
@require_permission("review:reject")
def reject_queued_policy(item_id: str):
    user = get_current_user()
    body = request.get_json(silent=True) or {}
    note = (body.get("note") or "").strip()
    item = get_queue_item(item_id)
    if not item:
        return jsonify({"error": "Queue item not found"}), 404
    if item["status"] != "pending":
        return jsonify({"error": f"Cannot reject: item status is '{item['status']}'"}), 400
    update_queue_status(item_id, "rejected", reviewed_by=user, review_note=note or "Rejected")
    audit_logger.log(user, "REJECT_POLICY", item["name"], item["namespace"], "SUCCESS",
                     f"queue_id={item_id}, submitter={item['submitted_by']}")
    return jsonify({"ok": True, "message": f"Policy '{item['name']}' rejected"})


@api_bp.route("/policies/queue/<item_id>", methods=["DELETE"])
@require_auth
def cancel_queued_policy(item_id: str):
    user = get_current_user()
    item = get_queue_item(item_id)
    if not item:
        return jsonify({"error": "Not found"}), 404
    from ..auth import current_user_has_permission
    if not current_user_has_permission("review:cancel") and item["submitted_by"] != user:
        return jsonify({"error": "Forbidden: can only cancel your own submissions"}), 403
    if item["status"] != "pending":
        return jsonify({"error": f"Cannot cancel: item status is '{item['status']}'"}), 400
    update_queue_status(item_id, "cancelled", reviewed_by=user, review_note="Cancelled by user")
    audit_logger.log(user, "CANCEL_REVIEW", item["name"], item["namespace"], "SUCCESS",
                     f"queue_id={item_id}")
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Policy Backup / Restore
# ---------------------------------------------------------------------------

@api_bp.route("/policies/backup", methods=["GET"])
@require_permission("policies:export")
def backup_policies():
    user = get_current_user()
    namespace = (request.args.get("namespace") or "default").strip() or "default"
    include_namespace = request.args.get("include_namespace", "1") not in ("0", "false", "False")
    include_cluster = request.args.get("include_cluster", "1") not in ("0", "false", "False")
    items = []

    try:
        if include_namespace:
            raw = custom_objects().list_namespaced_custom_object(
                group=VARMOR_GROUP, version=VARMOR_VERSION,
                namespace=namespace, plural=VARMOR_PLURAL,
            )
            for obj in raw.get("items", []):
                manifest, err = _strip_policy_manifest(obj)
                if not err:
                    ident = _backup_manifest_identity(manifest)
                    items.append({**ident, "manifest": manifest})

        if include_cluster:
            raw = custom_objects().list_cluster_custom_object(
                group=VARMOR_GROUP, version=VARMOR_VERSION,
                plural=VARMOR_CLUSTER_PLURAL,
            )
            for obj in raw.get("items", []):
                manifest, err = _strip_policy_manifest(obj)
                if not err:
                    ident = _backup_manifest_identity(manifest)
                    items.append({**ident, "manifest": manifest})
    except ApiException as exc:
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        logger.exception("Unexpected error building policy backup")
        return jsonify({"error": str(exc)}), 500

    audit_logger.log(user, "BACKUP_POLICIES", "policies", namespace, "SUCCESS", f"count={len(items)}")
    ts = _utc_backup_timestamp().replace(":", "").replace("-", "")[:15]
    filename = f"varmor-backup-{namespace}-{ts}.json"
    resp = jsonify({
        "version": POLICY_BACKUP_VERSION,
        "created_at": _utc_backup_timestamp(),
        "namespace": namespace,
        "items": items,
        "total": len(items),
    })
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


@api_bp.route("/policies/restore/preview", methods=["POST"])
@require_permission("policies:import")
def preview_policy_restore():
    body = request.get_json(silent=True) or {}
    conflict_action = (body.get("conflict_action") or "skip").strip()
    if conflict_action not in ("skip", "overwrite"):
        return jsonify({"error": "conflict_action must be 'skip' or 'overwrite'"}), 400
    entries, err = _backup_payload_entries(body.get("backup", body))
    if err:
        return jsonify({"error": err}), 400
    preview = _restore_preview_items(entries, conflict_action)
    return jsonify({
        "ok": True,
        "conflict_action": conflict_action,
        "items": preview,
        "total": len(preview),
        "valid": sum(1 for i in preview if i["valid"]),
        "errors": sum(1 for i in preview if not i["valid"]),
    })


@api_bp.route("/policies/restore", methods=["POST"])
@require_permission("policies:apply_direct")
def restore_policies():
    user = get_current_user()
    from ..auth import current_user_has_permission
    if not current_user_has_permission("policies:import"):
        return jsonify({"error": 'Forbidden: permission "policies:import" required'}), 403
    body = request.get_json(silent=True) or {}
    conflict_action = (body.get("conflict_action") or "skip").strip()
    if conflict_action not in ("skip", "overwrite"):
        return jsonify({"error": "conflict_action must be 'skip' or 'overwrite'"}), 400
    entries, err = _backup_payload_entries(body.get("backup", body))
    if err:
        return jsonify({"error": err}), 400

    results = []
    for entry in entries:
        ident = {k: entry.get(k) for k in ("kind", "scope", "namespace", "name", "mode", "enforcer")}
        if entry.get("error"):
            results.append({"index": entry["index"], "status": "error", "error": entry["error"], **ident})
            continue
        result = _apply_backup_manifest(entry["manifest"], conflict_action)
        result["index"] = entry["index"]
        result.update({k: v for k, v in ident.items() if v})
        results.append(result)

    failures = sum(1 for r in results if r.get("status") == "error")
    applied = sum(1 for r in results if r.get("status") in ("created", "overwritten"))
    audit_logger.log(user, "RESTORE_POLICIES", "policies", "cluster", "FAILURE" if failures else "SUCCESS",
                     f"applied={applied}, failures={failures}, total={len(results)}")
    return jsonify({"ok": failures == 0, "results": results, "applied": applied, "failures": failures})


@api_bp.route("/policies/restore/submit", methods=["POST"])
@require_operator
def submit_policy_restore_for_review():
    user = get_current_user()
    from ..auth import current_user_has_permission
    if not current_user_has_permission("policies:import"):
        return jsonify({"error": 'Forbidden: permission "policies:import" required'}), 403
    body = request.get_json(silent=True) or {}
    entries, err = _backup_payload_entries(body.get("backup", body))
    if err:
        return jsonify({"error": err}), 400

    import json as _json
    results = []
    for entry in entries:
        if entry.get("error"):
            results.append({"index": entry["index"], "status": "error", "error": entry["error"]})
            continue
        manifest = entry["manifest"]
        ident = _backup_manifest_identity(manifest)
        item_id = queue_policy(
            ident["name"], ident["namespace"] or "cluster", ident["scope"],
            _json.dumps(manifest), user,
        )
        results.append({"index": entry["index"], "status": "submitted", "id": item_id, **ident})

    failures = sum(1 for r in results if r.get("status") == "error")
    submitted = sum(1 for r in results if r.get("status") == "submitted")
    audit_logger.log(user, "SUBMIT_RESTORE", "policies", "cluster", "FAILURE" if failures else "SUCCESS",
                     f"submitted={submitted}, failures={failures}, total={len(results)}")
    return jsonify({"ok": failures == 0, "results": results, "submitted": submitted, "failures": failures}), 201


VARMOR_CLUSTER_PLURAL_APPLY = "varmorclusterpolicies"


@api_bp.route("/namespaces/<namespace>/models/<name>/apply", methods=["POST"])
@require_permission("models:apply")
def apply_model_as_policy(namespace: str, name: str):
    user = get_current_user()
    body = request.get_json(silent=True) or {}
    new_mode = body.get("mode", "DefenseInDepth")
    if new_mode != "DefenseInDepth":
        return jsonify({"error": "ArmorProfileModel can only be applied as DefenseInDepth"}), 400

    # Fetch the ArmorProfileModel to find its owning policy
    try:
        model = custom_objects().get_namespaced_custom_object(
            group=VARMOR_GROUP, version=VARMOR_VERSION,
            namespace=namespace, plural=ARMOR_PROFILE_MODEL_PLURAL, name=name,
        )
    except ApiException as exc:
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status

    # Resolve policy name from ownerReference, then strip varmor-<ns>- prefix
    policy_name = None
    for owner in model.get("metadata", {}).get("ownerReferences", []):
        if "Policy" in owner.get("kind", ""):
            policy_name = owner["name"]
            break
    if not policy_name:
        # Model name format: varmor-<namespace>-<policy-name>
        prefix = f"varmor-{namespace}-"
        policy_name = name[len(prefix):] if name.startswith(prefix) else name

    # Fetch the policy
    is_cluster = False
    try:
        policy = custom_objects().get_namespaced_custom_object(
            group=VARMOR_GROUP, version=VARMOR_VERSION,
            namespace=namespace, plural=VARMOR_PLURAL, name=policy_name,
        )
    except ApiException:
        try:
            policy = custom_objects().get_cluster_custom_object(
                group=VARMOR_GROUP, version=VARMOR_VERSION,
                plural=VARMOR_CLUSTER_PLURAL_APPLY, name=policy_name,
            )
            is_cluster = True
        except ApiException as exc2:
            return jsonify({"error": f"Policy '{policy_name}' not found: {_k8s_error_msg(exc2)}"}), 404

    policy_spec = policy.setdefault("spec", {}).setdefault("policy", {})
    old_mode = policy_spec.get("mode", "BehaviorModeling")
    enforcer = policy_spec.get("enforcer", "")
    enforcer_lower = enforcer.lower()

    if "bpf" in enforcer_lower:
        return jsonify({"error": "DefenseInDepth from a behavior model supports AppArmor and/or Seccomp, not BPF"}), 400

    did: dict = {}
    if "apparmor" in enforcer_lower:
        did["appArmor"] = {"profileType": "BehaviorModel"}
    if "seccomp" in enforcer_lower:
        did["seccomp"] = {"profileType": "BehaviorModel"}
    if not did:
        return jsonify({"error": "Behavior model policy must use AppArmor and/or Seccomp enforcer"}), 400
    if "allow_violations" in body:
        did["allowViolations"] = bool(body.get("allow_violations"))

    policy_spec["mode"] = "DefenseInDepth"
    policy_spec["defenseInDepth"] = did
    policy_spec.pop("modelingOptions", None)
    policy_spec.pop("enhanceProtect", None)

    try:
        if is_cluster:
            custom_objects().replace_cluster_custom_object(
                group=VARMOR_GROUP, version=VARMOR_VERSION,
                plural=VARMOR_CLUSTER_PLURAL_APPLY, name=policy_name, body=policy,
            )
        else:
            custom_objects().replace_namespaced_custom_object(
                group=VARMOR_GROUP, version=VARMOR_VERSION,
                namespace=namespace, plural=VARMOR_PLURAL, name=policy_name, body=policy,
            )
        audit_logger.log(user, "APPLY_MODEL", policy_name, namespace, "SUCCESS",
                         f"mode {old_mode} -> {new_mode}, model={name}")
        return jsonify({"ok": True, "policy": policy_name, "old_mode": old_mode, "new_mode": new_mode})
    except ApiException as exc:
        audit_logger.log(user, "APPLY_MODEL", policy_name, namespace, "FAILURE", str(exc.status))
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status


# ---------------------------------------------------------------------------
# ArmorProfile – per-node status
# ---------------------------------------------------------------------------

@api_bp.route("/namespaces/<namespace>/armor-profiles", methods=["GET"])
@require_permission("logs:view")
def list_armor_profiles(namespace: str):
    try:
        raw = custom_objects().list_namespaced_custom_object(
            group=VARMOR_GROUP, version=VARMOR_VERSION,
            namespace=namespace, plural=ARMOR_PROFILE_PLURAL,
        )
    except ApiException as exc:
        logger.error("K8s error listing armor profiles in %s: %s", namespace, exc)
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        logger.exception("Unexpected error listing armor profiles in %s", namespace)
        return jsonify({"error": str(exc)}), 500

    profiles = []
    for item in raw.get("items", []):
        meta = item.get("metadata", {})
        status_obj = item.get("status", {})
        desired = status_obj.get("desiredNumberLoaded", 0)
        current = status_obj.get("currentNumberLoaded", 0)
        node_conditions = []
        for cond in status_obj.get("conditions", []):
            node_conditions.append({
                "nodeName": cond.get("nodeName", ""),
                "type": cond.get("type", ""),
                "status": cond.get("status", ""),
                "reason": cond.get("reason", ""),
                "message": cond.get("message", ""),
                "lastTransitionTime": cond.get("lastTransitionTime", ""),
            })
        spec = item.get("spec", {})
        profiles.append({
            "name": meta.get("name", ""),
            "namespace": meta.get("namespace", namespace),
            "created_at": meta.get("creationTimestamp", ""),
            "desired": desired,
            "current": current,
            "ready": desired > 0 and current >= desired,
            "conditions": node_conditions,
            "enforcer": spec.get("profile", {}).get("enforcer", ""),
            "mode": spec.get("profile", {}).get("mode", ""),
        })
    return jsonify({"profiles": profiles})


# ---------------------------------------------------------------------------
# Violation Events – read /var/log/varmor/violations.log
# ---------------------------------------------------------------------------

_VIOL_LOG_PATH = os.environ.get("VARMOR_VIOLATION_LOG_PATH", "/var/log/varmor/violations.log")


def _parse_violation_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    # Try JSON first (zerolog format emitted by vArmor auditor)
    if line.startswith("{"):
        try:
            obj = json.loads(line)
            # vArmor uses camelCase: podNamespace, podName, containerName, profileName
            # eventTimestamp is Unix epoch seconds (uint64 integer)
            ts_raw = obj.get("eventTimestamp", 0)
            if isinstance(ts_raw, (int, float)) and ts_raw > 0:
                ts = datetime.datetime.utcfromtimestamp(ts_raw).strftime("%Y-%m-%dT%H:%M:%SZ")
            else:
                ts = obj.get("time") or obj.get("ts") or obj.get("timestamp", "")
            # "event" field contains the AppArmor/BPF/Seccomp event struct
            ev_obj = obj.get("event") or {}
            if not isinstance(ev_obj, dict):
                ev_obj = {}
            # BPF network events nest address/socket inside the event
            addr = ev_obj.get("address") or {}
            sock = ev_obj.get("socket") or {}
            if not isinstance(addr, dict):
                addr = {}
            if not isinstance(sock, dict):
                sock = {}
            # BPF path permissions is []string — join for display
            perms = ev_obj.get("permissions", "")
            if isinstance(perms, list):
                perms = ",".join(perms)
            pid_raw = obj.get("pid", "")
            return {
                "ts": ts,
                "namespace": obj.get("podNamespace", ""),
                "pod": obj.get("podName", ""),
                "container": obj.get("containerName", ""),
                "profile": obj.get("profileName", ""),
                "enforcer": obj.get("enforcer", ""),
                "action": str(obj.get("action", "")).upper(),
                "node": obj.get("nodeName", ""),
                "pid": str(pid_raw) if pid_raw else "",
                # AppArmor / generic
                "operation": ev_obj.get("operation", ""),
                "name": ev_obj.get("name", ev_obj.get("srcName", "")),
                "comm": ev_obj.get("comm", ""),
                "deniedMask": ev_obj.get("deniedMask", ""),
                "requestedMask": ev_obj.get("requestedMask", ""),
                # BPF path
                "path": ev_obj.get("path", ""),
                "permissions": perms,
                # BPF capability
                "capability": ev_obj.get("capability", ""),
                # BPF network
                "ip": addr.get("ip", ""),
                "port": str(addr.get("port", "")) if addr.get("port") else "",
                "domain": sock.get("domain", ""),
                "protocol": sock.get("protocol", ""),
                # Seccomp
                "syscall": ev_obj.get("syscall", ""),
                "exe": ev_obj.get("exe", ""),
                "subj": ev_obj.get("subj", ""),
                "raw": line,
            }
        except Exception:
            pass
    # zerolog key=value console fallback (unlikely in production)
    fields: dict[str, str] = {}
    for m in re.finditer(r'(\w+)=("([^"]*)"|\S+)', line):
        key = m.group(1)
        fields[key] = m.group(3) if m.group(3) is not None else m.group(2)
    if "msg" not in fields and "action" not in fields:
        return None
    return {
        "ts": fields.get("time", fields.get("ts", "")),
        "namespace": fields.get("podNamespace", fields.get("namespace", "")),
        "pod": fields.get("podName", fields.get("pod", "")),
        "container": fields.get("containerName", fields.get("container", "")),
        "profile": fields.get("profileName", fields.get("profile", "")),
        "enforcer": fields.get("enforcer", ""),
        "action": fields.get("action", fields.get("apparmor", "")).upper(),
        "node": fields.get("nodeName", ""),
        "pid": fields.get("pid", ""),
        "operation": fields.get("operation", fields.get("op", "")),
        "name": fields.get("name", fields.get("path", "")),
        "comm": fields.get("comm", ""),
        "deniedMask": "", "requestedMask": "", "path": "", "permissions": "",
        "capability": "", "ip": "", "port": "", "domain": "", "protocol": "",
        "syscall": "", "exe": "", "subj": "",
        "raw": line,
    }


@api_bp.route("/violation-events", methods=["GET"])
@require_permission("logs:violations")
def get_violation_events():
    log_path = _VIOL_LOG_PATH
    limit = _bounded_int_arg("limit", 200, 2000)
    namespace_filter = request.args.get("namespace", "")
    action_filter = request.args.get("action", "").upper()

    try:
        with open(log_path, "r", errors="replace") as f:
            all_lines = f.readlines()
    except FileNotFoundError:
        return jsonify({
            "events": [],
            "warn": (
                f"Violation log not found: {log_path}. "
                "Mount the host /var/log/varmor directory via hostPath volume, "
                "or set the VARMOR_VIOLATION_LOG_PATH env var."
            ),
        })
    except PermissionError:
        return jsonify({"events": [], "warn": f"Permission denied reading {log_path}."}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    events = []
    for raw in reversed(all_lines):
        if len(events) >= limit:
            break
        evt = _parse_violation_line(raw)
        if not evt:
            continue
        if namespace_filter and evt.get("namespace") != namespace_filter:
            continue
        # action=AUDIT also includes AUDIT|ALLOWED (both are audit-type events)
        if action_filter:
            ev_action = evt.get("action", "")
            audit_match = action_filter == "AUDIT" and ev_action in ("AUDIT", "AUDIT|ALLOWED")
            if not audit_match and ev_action != action_filter:
                continue
        events.append(evt)

    return jsonify({"events": events, "total": len(events), "log_path": log_path})


# ---------------------------------------------------------------------------
# Secrets Management – for NetworkProxy headerMutations.secretRef
# ---------------------------------------------------------------------------

@api_bp.route("/namespaces/<namespace>/secrets", methods=["GET"])
@require_operator
def list_secrets(namespace: str):
    try:
        result = core_v1().list_namespaced_secret(namespace=namespace)
    except ApiException as exc:
        logger.error("K8s error listing secrets in %s: %s", namespace, exc)
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        logger.exception("Unexpected error listing secrets in %s", namespace)
        return jsonify({"error": str(exc)}), 500

    secrets = []
    for s in result.items:
        secret_type = s.type or ""
        # Only expose Opaque and kubernetes.io/tls types
        if secret_type not in ("Opaque", "", "kubernetes.io/tls"):
            continue
        keys = list((s.data or {}).keys()) + list((s.string_data or {}).keys())
        secrets.append({
            "name": s.metadata.name,
            "namespace": s.metadata.namespace,
            "type": secret_type,
            "keys": sorted(set(keys)),
            "created_at": s.metadata.creation_timestamp.isoformat() if s.metadata.creation_timestamp else "",
        })
    return jsonify({"secrets": secrets})


@api_bp.route("/namespaces/<namespace>/secrets", methods=["POST"])
@require_admin
def create_secret(namespace: str):
    user = get_current_user()
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    data = body.get("data") or {}
    if not name:
        return jsonify({"error": "Secret name is required"}), 400
    if not isinstance(data, dict) or not data:
        return jsonify({"error": "data must be a non-empty object of key: value pairs"}), 400

    import base64
    string_data = {str(k).strip(): str(v) for k, v in data.items() if str(k).strip()}
    manifest = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name, "namespace": namespace},
        "type": "Opaque",
        "stringData": string_data,
    }
    try:
        from kubernetes import client as k8s_client
        core_v1().create_namespaced_secret(namespace=namespace, body=manifest)
        audit_logger.log(user, "CREATE_SECRET", name, namespace, "SUCCESS")
        return jsonify({"ok": True, "name": name}), 201
    except ApiException as exc:
        audit_logger.log(user, "CREATE_SECRET", name, namespace, "FAILURE", exc.reason or str(exc.status))
        logger.error("K8s error creating secret %s/%s: %s", namespace, name, exc)
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        logger.exception("Unexpected error creating secret %s/%s", namespace, name)
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Policy Import – create policy from raw YAML / JSON
# ---------------------------------------------------------------------------

@api_bp.route("/policies/import", methods=["POST"])
@require_permission("policies:import")
def import_policy():
    import yaml as pyyaml
    user = get_current_user()
    body = request.get_json(silent=True) or {}
    raw_yaml = (body.get("yaml") or "").strip()
    if not raw_yaml:
        return jsonify({"error": "yaml field is required"}), 400

    try:
        manifest = pyyaml.safe_load(raw_yaml)
    except Exception as exc:
        return jsonify({"error": f"YAML parse error: {exc}"}), 400

    if not isinstance(manifest, dict):
        return jsonify({"error": "YAML must be a single Kubernetes object"}), 400

    kind = manifest.get("kind", "")
    meta = manifest.get("metadata") or {}
    name = meta.get("name", "")
    namespace = meta.get("namespace", "default")

    if not name:
        return jsonify({"error": "metadata.name is required"}), 400
    if kind not in ("VarmorPolicy", "VarmorClusterPolicy"):
        return jsonify({"error": f"kind must be VarmorPolicy or VarmorClusterPolicy, got '{kind}'"}), 400

    # Ensure correct apiVersion
    manifest["apiVersion"] = f"{VARMOR_GROUP}/{VARMOR_VERSION}"

    try:
        if kind == "VarmorClusterPolicy":
            created = custom_objects().create_cluster_custom_object(
                group=VARMOR_GROUP, version=VARMOR_VERSION,
                plural=VARMOR_CLUSTER_PLURAL, body=manifest,
            )
            actual = created.get("metadata", {}).get("name", name)
            audit_logger.log(user, "IMPORT", actual, "cluster", "SUCCESS")
            return jsonify({"ok": True, "name": actual, "scope": "cluster"}), 201
        else:
            created = custom_objects().create_namespaced_custom_object(
                group=VARMOR_GROUP, version=VARMOR_VERSION,
                namespace=namespace, plural=VARMOR_PLURAL, body=manifest,
            )
            actual = created.get("metadata", {}).get("name", name)
            audit_logger.log(user, "IMPORT", actual, namespace, "SUCCESS")
            return jsonify({"ok": True, "name": actual, "scope": "namespace", "namespace": namespace}), 201
    except ApiException as exc:
        audit_logger.log(user, "IMPORT", name, namespace, "FAILURE", exc.reason or str(exc.status))
        logger.error("K8s error importing policy %s: %s", name, exc)
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        audit_logger.log(user, "IMPORT", name, namespace, "FAILURE", str(exc))
        logger.exception("Unexpected error importing policy %s", name)
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Policy Advisor – suggest built-in rules from ArmorProfileModel behavior data
# ---------------------------------------------------------------------------

def _advise_rules_from_model(dynamic: dict) -> list[dict]:
    """Analyse DynamicResult and suggest vArmor built-in rules."""
    suggestions: list[dict] = []

    def _rule(rule_id: str, reason: str, category: str = "attack"):
        suggestions.append({"rule": rule_id, "reason": reason, "category": category})

    # ── AppArmor-captured data ──
    aa = dynamic.get("appArmor") or {}

    # Files accessed
    for f in aa.get("files") or []:
        path = (f.get("path") or "").lower()
        if "/var/run/secrets/kubernetes.io" in path or "/run/secrets" in path:
            _rule("mitigate-sa-leak", "Accessed Kubernetes ServiceAccount token path")
        if path in ("/etc/passwd", "/etc/shadow"):
            _rule("disable-access-passwd" if "passwd" in path else "disable-access-shadow",
                  f"Read sensitive credential file {path}")
        if "/.ssh/" in path or path.endswith(".ssh"):
            _rule("disable-access-ssh-dir", "Accessed SSH directory")
        if path in ("/proc/kallsyms", "/proc/sys/kernel/core_pattern"):
            _rule("disallow-access-kallsyms" if "kallsyms" in path else "disallow-write-core-pattern",
                  f"Accessed kernel internal path {path}", "hardening")
        if "/sys/fs/cgroup" in path:
            _rule("disallow-mount-cgroupfs", "Accessed cgroupfs hierarchy", "hardening")
        if path.startswith("/etc/") and ("write" in str(f.get("permissions", "")) or "w" in str(f.get("permissions", ""))):
            _rule("disable-write-etc", "Wrote to /etc directory")

    # Executions
    for e in aa.get("executions") or []:
        exe = (e.get("path") or e if isinstance(e, str) else "").lower()
        if any(sh in exe for sh in ("/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/sh", "/usr/bin/bash")):
            _rule("disable-shell", f"Executed shell binary: {exe}")
        if "wget" in exe:
            _rule("disable-wget", f"Executed wget: {exe}")
        if "curl" in exe:
            _rule("disable-curl", f"Executed curl: {exe}")
        if "busybox" in exe:
            _rule("disable-busybox", f"Executed busybox: {exe}")
        if "chmod" in exe:
            _rule("disable-chmod", f"Executed chmod: {exe}")
        if any(s in exe for s in ("/bin/su", "/usr/bin/sudo", "/usr/bin/su")):
            _rule("disable-su-sudo", f"Executed su/sudo: {exe}")

    # Capabilities
    for cap in aa.get("capabilities") or []:
        cap_name = cap.get("capability") or cap if isinstance(cap, str) else ""
        if cap_name.upper() in ("ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_MODULE"):
            _rule(f"disable-cap-{cap_name.lower()}", f"Used elevated capability: {cap_name}", "hardening")

    # Network connections
    for net in aa.get("networks") or []:
        addr = str(net.get("remoteAddr") or net.get("addr") or "")
        if addr.startswith("169.254.169.254") or addr.startswith("100.96.0.96") or addr.startswith("100.100.100.200"):
            _rule("block-access-to-metadata-service", f"Connected to cloud metadata service: {addr}")

    # ── BPF-captured data ──
    bpf = dynamic.get("bpf") or {}
    for f in bpf.get("files") or []:
        path = (f.get("pattern") or "").lower()
        if "/var/run/secrets/kubernetes.io" in path:
            _rule("mitigate-sa-leak", "BPF: Accessed ServiceAccount token path")
        if "/var/run/docker.sock" in path or "/run/containerd" in path or "/run/crio" in path:
            _rule("block-access-to-container-runtime", "BPF: Accessed container runtime socket")

    for net in bpf.get("networks") or []:
        cidr = str(net.get("cidr") or net.get("ip") or "")
        if "169.254.169.254" in cidr or "100.96" in cidr or "100.100" in cidr:
            _rule("block-access-to-metadata-service", f"BPF: Connected to cloud metadata: {cidr}")

    # ── Seccomp-captured data ──
    sc = dynamic.get("seccomp") or {}
    syscalls = set(sc.get("syscalls") or [])
    if "unshare" in syscalls or "clone" in syscalls:
        _rule("disallow-abuse-user-ns", "Seccomp: Used namespace-related syscalls", "hardening")
    if "init_module" in syscalls or "finit_module" in syscalls:
        _rule("disallow-insmod", "Seccomp: Loaded kernel module", "hardening")
    if "bpf" in syscalls:
        _rule("disallow-load-bpf-prog", "Seccomp: Used BPF syscall", "hardening")
    if "userfaultfd" in syscalls:
        _rule("disallow-userfaultfd-creation", "Seccomp: Used userfaultfd syscall", "hardening")

    # Deduplicate
    seen_rules: set[str] = set()
    deduped = []
    for s in suggestions:
        if s["rule"] not in seen_rules:
            seen_rules.add(s["rule"])
            deduped.append(s)
    return deduped


@api_bp.route("/namespaces/<namespace>/models/<name>/advise", methods=["GET"])
@require_auth
def advise_policy(namespace: str, name: str):
    try:
        model = custom_objects().get_namespaced_custom_object(
            group=VARMOR_GROUP, version=VARMOR_VERSION,
            namespace=namespace, plural=ARMOR_PROFILE_MODEL_PLURAL, name=name,
        )
    except ApiException as exc:
        return jsonify({"error": _k8s_error_msg(exc)}), exc.status
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    data_field = model.get("data") or {}
    dynamic = data_field.get("dynamicResult") or {}

    suggestions = _advise_rules_from_model(dynamic)
    return jsonify({
        "model": name,
        "namespace": namespace,
        "suggestions": suggestions,
        "total": len(suggestions),
    })
