@echo off
setlocal enabledelayedexpansion

set "REPO_ROOT=%~dp0"

set "JDK_BIN=%REPO_ROOT%.jdk\bin"
if exist "%JDK_BIN%\javac.exe" goto :jdk_found

if not defined JAVA_HOME goto :try_path
if not exist "%JAVA_HOME%\bin\javac.exe" goto :try_path
set "JDK_BIN=%JAVA_HOME%\bin"
goto :jdk_found

:try_path
for /f "delims=" %%p in ('where javac 2^>nul') do (
    set "JDK_BIN=%%~dpp"
    if "!JDK_BIN:~-1!"=="\" set "JDK_BIN=!JDK_BIN:~0,-1!"
    goto :jdk_found
)

echo error: JDK not found (checked .jdk\bin, JAVA_HOME\bin, PATH)
echo   unpack a portable JDK 21 (Eclipse Temurin) into .jdk\ at the repository root,
echo   or set JAVA_HOME to an existing JDK 21+.
exit /b 1

:jdk_found
set "JAVAC=%JDK_BIN%\javac.exe"
set "JAR_TOOL=%JDK_BIN%\jar.exe"

set "CORE_JAR=%REPO_ROOT%dist\eds-check-core.jar"
if exist "%CORE_JAR%" goto :core_ok
echo error: %CORE_JAR% not found
echo   build the core first: build.bat
exit /b 1
:core_ok

set "SRC_DIR=%REPO_ROOT%src\gui\java"
set "BUILD_DIR=%REPO_ROOT%build\gui\classes"
set "DIST_DIR=%REPO_ROOT%dist"
set "LIB_DIR=%REPO_ROOT%lib"

if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
mkdir "%BUILD_DIR%"

set "SOURCES_FILE=%TEMP%\eds-check-sources-gui.txt"
if exist "%SOURCES_FILE%" del "%SOURCES_FILE%"
dir /s /b "%SRC_DIR%\*.java" > "%SOURCES_FILE%"

set "KALKAN_JAR=%REPO_ROOT%lib\kalkancrypt-0.7.6-certified.jar"
set "CP=%CORE_JAR%;%KALKAN_JAR%"
for %%f in ("%LIB_DIR%\*.jar") do set "CP=!CP!;%%f"

"%JAVAC%" -cp "!CP!" -d "%BUILD_DIR%" @"%SOURCES_FILE%"
if errorlevel 1 exit /b 1

del "%SOURCES_FILE%"

if exist "%REPO_ROOT%src\gui\resources" xcopy /E /I /Y /Q "%REPO_ROOT%src\gui\resources" "%BUILD_DIR%" >nul

set "MANIFEST_EXTRA=%REPO_ROOT%build\gui\premain-manifest.txt"
echo Premain-Class: kz.edscheck.gui.GuiAgent> "%MANIFEST_EXTRA%"

"%JAR_TOOL%" --create --file "%DIST_DIR%\eds-check-gui.jar" --manifest "%MANIFEST_EXTRA%" --main-class kz.edscheck.gui.GuiMain -C "%BUILD_DIR%" .
if errorlevel 1 exit /b 1
del "%MANIFEST_EXTRA%"

echo built: %DIST_DIR%\eds-check-gui.jar (run bin\EDScheck.bat, classpath includes dist\eds-check-core.jar)
endlocal
