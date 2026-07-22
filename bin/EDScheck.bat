@echo off
setlocal enabledelayedexpansion

set "REPO_ROOT=%~dp0.."
for %%i in ("%REPO_ROOT%") do set "REPO_ROOT=%%~fi"

set "CORE_JAR=%REPO_ROOT%\dist\eds-check-core.jar"
set "GUI_JAR=%REPO_ROOT%\dist\eds-check-gui.jar"
set "KALKAN_JAR=%REPO_ROOT%\lib\kalkancrypt-0.7.6-certified.jar"
set "LIB_DIR=%REPO_ROOT%\lib"
set "CERTS_DIR=%REPO_ROOT%\certs"

set "JDK_BIN=%REPO_ROOT%\.jdk\bin"
if exist "%JDK_BIN%\java.exe" goto :jdk_found

if not defined JAVA_HOME goto :try_path
if not exist "%JAVA_HOME%\bin\java.exe" goto :try_path
set "JDK_BIN=%JAVA_HOME%\bin"
goto :jdk_found

:try_path
for /f "delims=" %%p in ('where java 2^>nul') do (
    set "JDK_BIN=%%~dpp"
    if "!JDK_BIN:~-1!"=="\" set "JDK_BIN=!JDK_BIN:~0,-1!"
    goto :jdk_found
)

echo error: JDK not found (checked .jdk\bin, JAVA_HOME\bin, PATH)
echo   unpack a portable JDK 21 (Eclipse Temurin) into .jdk\ at the repository root,
echo   or set JAVA_HOME to an existing JDK 21+.
exit /b 1

:jdk_found
set "JDK_JAVA=%JDK_BIN%\java.exe"

if exist "%CORE_JAR%" if exist "%GUI_JAR%" goto :jars_ok
echo error: core/GUI jars not built
echo   build them first: build.bat ^&^& build-gui.bat
exit /b 1
:jars_ok

set "CP=%GUI_JAR%;%CORE_JAR%;%KALKAN_JAR%"
for %%f in ("%LIB_DIR%\*.jar") do set "CP=!CP!;%%f"

cd /d "%REPO_ROOT%"

"%JDK_JAVA%" -cp "!CP!" -Dkz.edscheck.kalkanJar="%KALKAN_JAR%" -Dkz.edscheck.libDir="%LIB_DIR%" -Dkz.edscheck.certsDir="%CERTS_DIR%" -Dflatlaf.nativeLibraryPath="%LIB_DIR%" kz.edscheck.gui.GuiMain
