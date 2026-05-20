import logging

from kubernetes import client, config
from kubernetes.config import ConfigException

logger = logging.getLogger(__name__)

VARMOR_GROUP = "crd.varmor.org"
VARMOR_VERSION = "v1beta1"
VARMOR_PLURAL = "varmorpolicies"

_k8s_ready = False


def _ensure_configured() -> None:
    global _k8s_ready
    if _k8s_ready:
        return
    try:
        config.load_incluster_config()
        logger.info("Kubernetes: using in-cluster config")
    except ConfigException:
        config.load_kube_config()
        logger.info("Kubernetes: using local kubeconfig")
    _k8s_ready = True


def apps_v1() -> client.AppsV1Api:
    _ensure_configured()
    return client.AppsV1Api()


def custom_objects() -> client.CustomObjectsApi:
    _ensure_configured()
    return client.CustomObjectsApi()
