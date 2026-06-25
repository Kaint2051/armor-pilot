"""ArmorPilot Linux launcher — entry point for the PyInstaller binary in the .deb."""
import os
import sys


def _base_path() -> str:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _setup_paths():
    base = _base_path()
    if base not in sys.path:
        sys.path.insert(0, base)


PORT = int(os.environ.get("PORT", "5000"))
HOST = os.environ.get("HOST", "0.0.0.0")


def main():
    _setup_paths()

    from app.main import app as flask_app
    from waitress import serve

    print(f"[ArmorPilot] Listening on http://{HOST}:{PORT}", flush=True)
    serve(flask_app, host=HOST, port=PORT, threads=4)


if __name__ == "__main__":
    main()
