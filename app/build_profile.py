"""Development build profile.

Container builds replace this module before compiling the application. Keep
production trust material out of the source tree.
"""

BUILD_EDITION = "development"
BUILD_REVISION = "source"
LICENSE_PUBLIC_KEY = ""
ALLOW_RUNTIME_PUBLIC_KEY_OVERRIDE = True
ALLOW_HS256_LICENSES = False
BUILTIN_TRIAL_CAPABLE = False
