"""ArmorPilot Windows launcher — entry point for the PyInstaller .exe bundle."""
import os
import sys
import threading
import time
import webbrowser


# ---------------------------------------------------------------------------
# Frozen-path helpers (PyInstaller onefile / onedir)
# ---------------------------------------------------------------------------

def _base_path() -> str:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _exe_dir() -> str:
    """Directory that contains the actual .exe (not the temp extraction dir)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _setup_paths():
    base = _base_path()
    if base not in sys.path:
        sys.path.insert(0, base)


# ---------------------------------------------------------------------------
# Config / first-run setup
# ---------------------------------------------------------------------------

def _load_env():
    """Load ArmorPilot.env from the .exe directory if present."""
    env_file = os.path.join(_exe_dir(), "ArmorPilot.env")
    if os.path.isfile(env_file):
        from dotenv import load_dotenv
        load_dotenv(env_file, override=False)


def _set_windows_data_defaults():
    """Set Windows-friendly data directory defaults if not already configured."""
    appdata = os.environ.get("APPDATA") or os.path.expanduser("~")
    data_dir = os.path.join(appdata, "ArmorPilot", "data")
    os.makedirs(data_dir, exist_ok=True)

    if not os.environ.get("DB_PATH"):
        os.environ["DB_PATH"] = os.path.join(data_dir, "users.db")
    if not os.environ.get("ARMORPILOT_LICENSE_FILE"):
        os.environ["ARMORPILOT_LICENSE_FILE"] = os.path.join(data_dir, "license.json")
    if not os.environ.get("ARMORPILOT_INSTALLATION_KEY_FILE"):
        os.environ["ARMORPILOT_INSTALLATION_KEY_FILE"] = os.path.join(data_dir, "installation-private.pem")
    if not os.environ.get("ARMORPILOT_INSTALLATION_METADATA_FILE"):
        os.environ["ARMORPILOT_INSTALLATION_METADATA_FILE"] = os.path.join(data_dir, "installation.json")


def _ensure_first_run_config():
    """
    Check whether first-run credentials are present.  If the database does
    not exist yet and ADMIN_USER / ADMIN_PASS are unset we prompt the user
    interactively rather than crashing with a RuntimeError.
    """
    db_path = os.environ.get("DB_PATH", "")
    if os.path.isfile(db_path):
        return  # Existing install — credentials already seeded

    if os.environ.get("ADMIN_USER") and len(os.environ.get("ADMIN_PASS", "")) >= 12:
        return  # Already configured via env / env-file

    print()
    print("=" * 60)
    print("  ArmorPilot — First-Run Setup")
    print("=" * 60)
    print()
    print("No existing database found.  Please create an admin account.")
    print("Tip: set ADMIN_USER and ADMIN_PASS in ArmorPilot.env to skip")
    print("     this prompt on future reinstalls.")
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
# Server + browser
# ---------------------------------------------------------------------------

def _open_browser(port: int) -> None:
    time.sleep(2)
    webbrowser.open(f"http://127.0.0.1:{port}")


def main():
    _setup_paths()
    _load_env()
    _set_windows_data_defaults()
    _ensure_first_run_config()

    # Read PORT/HOST after env files are loaded so ArmorPilot.env values apply.
    port = int(os.environ.get("PORT", "5000"))
    host = os.environ.get("HOST", "0.0.0.0")

    from app.main import app as flask_app
    from waitress import serve

    print(f"[ArmorPilot] Listening on http://localhost:{port}")
    print("[ArmorPilot] Press Ctrl+C to stop.")
    sys.stdout.flush()

    threading.Thread(target=_open_browser, args=(port,), daemon=True).start()
    serve(flask_app, host=host, port=port, threads=4)


if __name__ == "__main__":
    main()
