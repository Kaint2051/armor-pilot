"""ArmorPilot Linux launcher — entry point for the PyInstaller binary in the .deb."""
import os
import sys


# ---------------------------------------------------------------------------
# Frozen-path helpers (PyInstaller onefile)
# ---------------------------------------------------------------------------

def _base_path() -> str:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _setup_paths() -> None:
    base = _base_path()
    if base not in sys.path:
        sys.path.insert(0, base)


# ---------------------------------------------------------------------------
# Mode detection
# ---------------------------------------------------------------------------

def _is_service_mode() -> bool:
    """True when stdin has no TTY — running under systemd or in a pipeline."""
    try:
        return not sys.stdin.isatty()
    except Exception:
        return True


def _is_root() -> bool:
    try:
        return os.getuid() == 0
    except AttributeError:
        return False


# ---------------------------------------------------------------------------
# Data / config paths
# ---------------------------------------------------------------------------

def _data_dir() -> str:
    explicit = os.environ.get("ARMORPILOT_DATA_DIR")
    if explicit:
        return explicit
    if _is_root() or _is_service_mode():
        return "/var/lib/armor-pilot"
    xdg = os.environ.get(
        "XDG_DATA_HOME", os.path.join(os.path.expanduser("~"), ".local", "share")
    )
    return os.path.join(xdg, "armor-pilot")


def _env_file() -> str:
    system_cfg = "/etc/armor-pilot/armor-pilot.env"
    if os.path.isfile(system_cfg):
        return system_cfg
    return os.path.join(_data_dir(), "armor-pilot.env")


# ---------------------------------------------------------------------------
# Environment setup
# ---------------------------------------------------------------------------

def _load_env() -> None:
    cfg = _env_file()
    if os.path.isfile(cfg):
        from dotenv import load_dotenv
        load_dotenv(cfg, override=False)


def _set_linux_data_defaults() -> None:
    data = _data_dir()
    os.makedirs(data, exist_ok=True)

    # db.py reads DB_PATH at module level (no ARMORPILOT_ prefix)
    if not os.environ.get("DB_PATH"):
        os.environ["DB_PATH"] = os.path.join(data, "users.db")
    if not os.environ.get("ARMORPILOT_LICENSE_FILE"):
        os.environ["ARMORPILOT_LICENSE_FILE"] = os.path.join(data, "license.json")
    if not os.environ.get("ARMORPILOT_INSTALLATION_KEY_FILE"):
        os.environ["ARMORPILOT_INSTALLATION_KEY_FILE"] = os.path.join(data, "installation-private.pem")
    if not os.environ.get("ARMORPILOT_INSTALLATION_METADATA_FILE"):
        os.environ["ARMORPILOT_INSTALLATION_METADATA_FILE"] = os.path.join(data, "installation.json")


def _ensure_first_run_config() -> None:
    db_path = os.environ.get("DB_PATH", "")
    if os.path.isfile(db_path):
        return
    if os.environ.get("ADMIN_USER") and len(os.environ.get("ADMIN_PASS", "")) >= 12:
        return

    if _is_service_mode():
        print(
            "ERROR: No existing database and ADMIN_USER / ADMIN_PASS are not set.\n"
            "       Set them in /etc/armor-pilot/armor-pilot.env and restart.",
            file=sys.stderr,
        )
        sys.exit(1)

    print()
    print("=" * 60)
    print("  ArmorPilot — First-Run Setup")
    print("=" * 60)
    print()
    print("No database found. Create an admin account.")
    print("Tip: set ADMIN_USER / ADMIN_PASS in")
    print("     /etc/armor-pilot/armor-pilot.env to skip this prompt.")
    print()

    import getpass

    while True:
        username = input("  Admin username: ").strip()
        if username:
            break
        print("  Username cannot be empty.")

    while True:
        password = getpass.getpass("  Admin password (min 12 chars): ")
        if len(password) >= 12:
            break
        print("  Password must be at least 12 characters.")

    os.environ["ADMIN_USER"] = username
    os.environ["ADMIN_PASS"] = password
    print()


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

def main() -> None:
    _setup_paths()
    _load_env()
    _set_linux_data_defaults()
    _ensure_first_run_config()

    # Read PORT/HOST after env files are loaded so config file values apply.
    port = int(os.environ.get("PORT", "5000"))
    host = os.environ.get("HOST", "0.0.0.0")

    from app.main import app as flask_app
    from waitress import serve

    print(f"[ArmorPilot] Data : {os.environ.get('DB_PATH', '(unknown)')}", flush=True)
    print(f"[ArmorPilot] URL  : http://{host}:{port}", flush=True)
    serve(flask_app, host=host, port=port, threads=8)


if __name__ == "__main__":
    main()
