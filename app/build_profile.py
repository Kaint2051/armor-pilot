"""Development build profile.

Container builds replace this module before compiling the application. Keep
production trust material out of the source tree.
"""

BUILD_EDITION = "development"
BUILD_REVISION = "source"
LICENSE_PUBLIC_KEY = "OrsGfpk+/4XCzmE/m/CGhXSRFrKgQz8GQqSBcmA/5IE="
ALLOW_RUNTIME_PUBLIC_KEY_OVERRIDE = True
ALLOW_HS256_LICENSES = True
BUILTIN_TRIAL_CAPABLE = True
