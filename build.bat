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

set "SRC_DIR=%REPO_ROOT%src\main\java"
set "BUILD_DIR=%REPO_ROOT%build\classes"
set "DIST_DIR=%REPO_ROOT%dist"
set "LIB_DIR=%REPO_ROOT%lib"

if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
if exist "%DIST_DIR%" rmdir /s /q "%DIST_DIR%"
mkdir "%BUILD_DIR%"
mkdir "%DIST_DIR%"

set "SOURCES_FILE=%TEMP%\eds-check-sources-main.txt"
if exist "%SOURCES_FILE%" del "%SOURCES_FILE%"
dir /s /b "%SRC_DIR%\*.java" > "%SOURCES_FILE%"

set "CP=%REPO_ROOT%lib\kalkancrypt-0.7.6-certified.jar"
for %%f in ("%LIB_DIR%\*.jar") do set "CP=!CP!;%%f"

"%JAVAC%" -cp "!CP!" -d "%BUILD_DIR%" @"%SOURCES_FILE%"
if errorlevel 1 exit /b 1

del "%SOURCES_FILE%"

if exist "%REPO_ROOT%src\main\resources" xcopy /E /I /Y /Q "%REPO_ROOT%src\main\resources" "%BUILD_DIR%" >nul

"%JAR_TOOL%" --create --file "%DIST_DIR%\eds-check-core.jar" -C "%BUILD_DIR%" .
if errorlevel 1 exit /b 1

echo built: %DIST_DIR%\eds-check-core.jar
endlocal
