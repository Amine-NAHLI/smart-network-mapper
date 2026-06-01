@echo off
REM Build SNM.exe — necessite ~2 Go libres sur le lecteur du projet
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Creation du venv...
    python -m venv .venv
)

echo Installation des dependances...
.venv\Scripts\python.exe -m pip install -r requirements.txt pyinstaller -q
if errorlevel 1 (
    echo ECHEC installation dependances.
    pause
    exit /b 1
)

echo.
echo Fermeture de SNM.exe si ouvert...
taskkill /F /IM SNM.exe >nul 2>&1
timeout /t 2 /nobreak >nul

echo Nettoyage build\...
if exist build rmdir /s /q build

echo Nettoyage dist\...
if exist dist (
    rmdir /s /q dist 2>nul
    if exist dist (
        echo.
        echo ========================================
        echo  ERREUR : impossible de supprimer dist\
        echo ========================================
        echo  1. Fermez toutes les fenetres SNM
        echo  2. Fermez l'explorateur dans dist\SNM
        echo  3. Relancez build.bat
        echo.
        echo  Si un telechargement etait en cours, le cache HF
        echo  est maintenant dans %%LOCALAPPDATA%%\SmartNetworkMapper\
        echo ========================================
        pause
        exit /b 1
    )
)

echo.
echo Build PyInstaller en cours (2-5 min)...
.venv\Scripts\pyinstaller.exe build.spec --noconfirm
if errorlevel 1 (
    echo.
    echo ========================================
    echo  BUILD ECHEC - voir l'erreur ci-dessus
    echo ========================================
    pause
    exit /b 1
)

if not exist "dist\SNM\SNM.exe" (
    echo.
    echo BUILD ECHEC : dist\SNM\SNM.exe introuvable.
    pause
    exit /b 1
)

echo.
echo ========================================
echo  BUILD OK : dist\SNM\SNM.exe
echo.
echo  Distribution : copiez TOUT le dossier dist\SNM\
echo  1er lancement : UAC admin + telechargement HF ~5.1 Go
echo  Modeles finaux : dist\SNM\model\
echo  Cache HF temporaire : %%LOCALAPPDATA%%\SmartNetworkMapper\
echo ========================================

pause
