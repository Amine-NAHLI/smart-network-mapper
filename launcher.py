import ctypes
import sys
import os

from snm_paths import get_base_dir, get_model_dir


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    if getattr(sys, "frozen", False):
        executable = sys.executable
        params = ""
    else:
        executable = sys.executable
        params = f'"{os.path.abspath(__file__)}"'

    ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        executable,
        params,
        None,
        1,
    )
    sys.exit(0)


def models_exist(base_dir=None):
    model_path = os.path.join(
        base_dir or get_base_dir(), "model", "vulnerability_model.pkl"
    )
    return os.path.isfile(model_path)


def launch():
    base = get_base_dir()
    os.makedirs(get_model_dir(), exist_ok=True)

    if models_exist(base):
        from app import run_app
        run_app()
    else:
        from model_downloader_gui import run_downloader
        run_downloader()


if __name__ == "__main__":
    if not is_admin():
        relaunch_as_admin()
    else:
        launch()
