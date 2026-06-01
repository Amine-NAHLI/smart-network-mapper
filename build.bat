@echo off
REM Build SNM.exe — nécessite ~2 Go d'espace disque libre sur le lecteur du projet
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Creation du venv...
    python -m venv .venv
)

echo Installation des dependances...
.venv\Scripts\python.exe -m pip install -r requirements.txt pyinstaller -q

echo Nettoyage build / dist...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo Build PyInstaller en cours (2-5 min)...
.venv\Scripts\pyinstaller.exe build.spec --noconfirm

if exist "dist\SNM\SNM.exe" (
    echo.
    echo ========================================
    echo  BUILD OK : dist\SNM\SNM.exe
    echo  Copiez tout le dossier dist\SNM\
    echo  Les modeles IA se telechargent au 1er lancement.
    echo ========================================
) else (
    echo BUILD ECHEC - voir les messages ci-dessus.
    exit /b 1
)

pause
