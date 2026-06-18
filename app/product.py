PRODUCT_NAME = "ArmorPilot"
PRODUCT_SLUG = "armor-pilot"
PRODUCT_TAGLINE = "Kubernetes Runtime Security Management Platform"
UPSTREAM_ENGINE = "vArmor"
CORE_EDITION = "community"
ENTERPRISE_EDITION = "enterprise"
DEVELOPER_EDITION = "developer"


OPEN_CORE_PACKS = {
    "community": [
        "baseline",
        "cve",
        "compliance",
        "workload",
        "network",
    ],
    "enterprise": [
        "data-protection",
        "platform-infra",
        "incident-response",
    ],
}

FEATURE_CATALOG = {
    "templates:data_protection": {
        "name": "Data Protection Templates",
        "edition": ENTERPRISE_EDITION,
        "description": "Templates for TLS keys, secret clients, backup controllers, and sensitive data paths.",
    },
    "templates:platform_infra": {
        "name": "Platform Infrastructure Templates",
        "edition": ENTERPRISE_EDITION,
        "description": "Templates for database, broker, auth, DNS, CSI, CNI, and admission-controller workloads.",
    },
    "templates:incident_response": {
        "name": "Incident Response Templates",
        "edition": ENTERPRISE_EDITION,
        "description": "Containment and forensic-hold templates for active compromise response.",
    },
}

EDITION_MATRIX = [
    {
        "id": CORE_EDITION,
        "name": "Community",
        "description": "Open-core management platform with core policy operations and general-purpose templates.",
        "template_packs": OPEN_CORE_PACKS["community"],
        "license_required": False,
    },
    {
        "id": ENTERPRISE_EDITION,
        "name": "Enterprise",
        "description": "Commercial edition unlocked by signed license features.",
        "template_packs": OPEN_CORE_PACKS["enterprise"],
        "license_required": True,
    },
]


def effective_edition(license_status: dict) -> str:
    if license_status.get("valid"):
        payload = license_status.get("payload") or {}
        return payload.get("edition") or ENTERPRISE_EDITION
    if license_status.get("fail_open"):
        return DEVELOPER_EDITION
    return CORE_EDITION


def get_product_payload(license_status: dict | None = None) -> dict:
    license_status = license_status or {}
    return {
        "name": PRODUCT_NAME,
        "slug": PRODUCT_SLUG,
        "tagline": PRODUCT_TAGLINE,
        "upstream_engine": UPSTREAM_ENGINE,
        "open_core": True,
        "effective_edition": effective_edition(license_status),
        "editions": EDITION_MATRIX,
        "feature_catalog": FEATURE_CATALOG,
        "core_template_packs": OPEN_CORE_PACKS["community"],
        "enterprise_template_packs": OPEN_CORE_PACKS["enterprise"],
    }
