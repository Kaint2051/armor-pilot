# Copyright 2026 ArmorPilot Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os


PRODUCT_ENV_PREFIX = "ARMORPILOT_"
LEGACY_ENV_PREFIX = "VARMOR_"


def get_product_env(name: str, default: str = "") -> str:
    """Return an ArmorPilot setting, falling back to its legacy vArmor name."""
    primary = os.environ.get(f"{PRODUCT_ENV_PREFIX}{name}")
    if primary is not None:
        return primary
    legacy = os.environ.get(f"{LEGACY_ENV_PREFIX}{name}")
    if legacy is not None:
        return legacy
    return default


def get_product_bool_env(name: str, default: bool) -> bool:
    raw = get_product_env(name)
    if not raw:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}
