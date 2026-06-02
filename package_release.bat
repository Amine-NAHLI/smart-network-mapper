@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

if not exist "dist\SNM\SNM.exe" (
    echo dist\SNM\SNM.exe introuvable. Lancez d'abord build.bat
    pause
    exit /b 1
)

set RELEASE=release
set NAME=SNM_Windows_Portable
set DEST=%RELEASE%\%NAME%
set PACKAGE_TYPE=Leger

echo.
echo Creation du package portable...
if not exist "%RELEASE%" mkdir "%RELEASE%"
if exist "%DEST%" rmdir /s /q "%DEST%"
mkdir "%DEST%"

echo Copie de dist\SNM\...
xcopy "dist\SNM\*" "%DEST%\" /E /I /H /Y >nul

copy /Y "INSTALL_WINDOWS.txt" "%DEST%\" >nul

if exist "model\vulnerability_model.pkl" (
    for %%A in ("model\vulnerability_model.pkl") do set SIZE=%%~zA
    if !SIZE! GTR 100000000 (
        echo Copie des modeles IA vers le package COMPLET - environ 5 Go...
        if not exist "%DEST%\model" mkdir "%DEST%\model"
        copy /Y "model\*.pkl" "%DEST%\model\" >nul
        set PACKAGE_TYPE=Complet
    )
)

echo.
echo ========================================
echo  PACKAGE PRET
echo ========================================
echo  Dossier portable :
echo  %CD%\%DEST%
echo.

if "%PACKAGE_TYPE%"=="Complet" goto :complet
goto :leger

:leger
set ZIP=%RELEASE%\%NAME%_Leger.zip
if exist "%ZIP%" del /F /Q "%ZIP%" 2>nul
echo  Creation du ZIP leger...
powershell -NoProfile -Command "Compress-Archive -Path '%DEST%' -DestinationPath '%ZIP%' -Force"
if exist "%ZIP%" (
    echo  ZIP : %CD%\%ZIP%
) else (
    echo  ZIP leger non cree - utilisez le dossier ci-dessus.
)
goto :fin

:complet
echo  Version COMPLETE - copiez le DOSSIER entier sur cle USB.
echo  Pas de ZIP automatique : limite Windows 2 Go avec Compress-Archive.
echo.
echo  ZIP optionnel manuel ^(10-30 min^) :
echo    cd release
echo    tar -a -c -f SNM_Windows_Portable_Complet.zip SNM_Windows_Portable
goto :fin

:fin
echo.
echo  Sur un nouveau PC Windows :
echo    1. Copiez le dossier SNM_Windows_Portable
echo    2. Lisez INSTALL_WINDOWS.txt
echo    3. Lancez SNM.exe et acceptez UAC
echo ========================================
pause
