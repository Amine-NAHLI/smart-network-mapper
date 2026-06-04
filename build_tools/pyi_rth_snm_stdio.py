"""
Hook PyInstaller — s'exécute avant tout import applicatif.
Corrige stdout/stderr None (exe sans console) pour huggingface_hub / tqdm.
"""
import os
import sys

if getattr(sys, "frozen", False):
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8", errors="replace")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8", errors="replace")
    _local = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
    _cache = os.path.join(_local, "SmartNetworkMapper", "hf_cache")
    os.makedirs(_cache, exist_ok=True)
    os.environ["HF_HOME"] = _cache
    os.environ["HUGGINGFACE_HUB_CACHE"] = os.path.join(_cache, "hub")
    os.makedirs(os.environ["HUGGINGFACE_HUB_CACHE"], exist_ok=True)
    os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    os.environ["TQDM_DISABLE"] = "1"
