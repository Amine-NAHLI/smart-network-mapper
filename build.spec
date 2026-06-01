# build.spec — PyInstaller (Smart Network Mapper)
# Les fichiers .pkl (~5 Go) ne sont PAS inclus : téléchargement au 1er lancement.
import os
from PyInstaller.utils.hooks import collect_data_files

block_cipher = None

customtkinter_datas = collect_data_files("customtkinter")

# Empêcher PyInstaller d'embarquer des .pkl s'ils sont présents dans model/
_model_dir = os.path.join(os.path.dirname(SPEC), "model")
_model_datas = []
if os.path.isdir(_model_dir):
    for name in os.listdir(_model_dir):
        if name.endswith(".py"):
            _model_datas.append(
                (os.path.join(_model_dir, name), "model")
            )

a = Analysis(
    ["launcher.py"],
    pathex=["."],
    binaries=[],
    datas=[
        *customtkinter_datas,
        ("assets", "assets"),
        ("reporter", "reporter"),
        ("scanner", "scanner"),
        *_model_datas,
    ],
    hiddenimports=[
        "app",
        "model_downloader_gui",
        "model.predictor",
        "snm_paths",
        "reporter.html_generator",
        "sklearn.utils._typedefs",
        "sklearn.utils._heap",
        "sklearn.utils._sorting",
        "sklearn.utils._vector_sentinel",
        "sklearn.neighbors._partition_nodes",
        "sklearn.tree._utils",
        "sklearn.ensemble._forest",
        "pandas._libs.tslibs.np_datetime",
        "pandas._libs.tslibs.nattype",
        "pandas._libs.tslibs.timedeltas",
        "pandas._libs.tslibs.timestamps",
        "pandas._libs.tslibs.period",
        "pandas._libs.tslibs.offsets",
        "pandas._libs.tslibs.parsing",
        "pandas._libs.hashtable",
        "pandas._libs.index",
        "pandas._libs.lib",
        "scapy.layers.all",
        "scapy.contrib",
        "psutil",
        "joblib",
        "huggingface_hub",
        "customtkinter",
        "colorama",
        "tqdm",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "outputs",
        "tests",
        "matplotlib",
        "notebook",
        "IPython",
        "pytest",
        "torch",
        "torchvision",
        "torchaudio",
        "tensorflow",
        "keras",
        "cv2",
        "PIL.ImageQt",
        "wx",
        "PyQt5",
        "PyQt6",
        "PySide2",
        "PySide6",
        "main",
        "download_models",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SNM",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    uac_admin=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="SNM",
)
