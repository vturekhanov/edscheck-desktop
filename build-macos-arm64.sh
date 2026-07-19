#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
    echo "ошибка: этот скрипт — только для macOS (jpackage упаковывает нативными инструментами хост-ОС, кросс-сборка невозможна)" >&2
    exit 1
fi
if [ "$(uname -m)" != "arm64" ]; then
    echo "ошибка: этот скрипт — только для macOS arm64 (обнаружено: $(uname -m))" >&2
    exit 1
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$DIR"

PKG_TYPE="app-image"
case "${1:-}" in
    "") ;;
    --type=*) PKG_TYPE="${1#--type=}" ;;
    --type)
        PKG_TYPE="${2:-}"
        if [ -z "$PKG_TYPE" ]; then
            echo "ошибка: --type требует значения (app-image|dmg|pkg)" >&2
            exit 1
        fi
        ;;
    *)
        echo "ошибка: неизвестный аргумент '$1' (ожидается --type app-image|dmg|pkg, по умолчанию app-image)" >&2
        exit 1
        ;;
esac
case "$PKG_TYPE" in
    app-image|dmg|pkg) ;;
    *)
        echo "ошибка: --type должен быть app-image, dmg или pkg (получено: $PKG_TYPE)" >&2
        exit 1
        ;;
esac

resolve_jdk_home() {
    if [ -x "$REPO_ROOT/.jdk/bin/jpackage" ]; then
        echo "$REPO_ROOT/.jdk"
        return 0
    fi
    if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/jpackage" ]; then
        echo "$JAVA_HOME"
        return 0
    fi
    if command -v jpackage >/dev/null 2>&1; then
        dirname "$(dirname "$(command -v jpackage)")"
        return 0
    fi
    return 1
}

JDK_HOME="$(resolve_jdk_home)" || {
    echo "ошибка: не найден JDK 21 с jpackage (проверены .jdk/bin, \$JAVA_HOME/bin, PATH)" >&2
    echo "  распакуйте портативный JDK 21 (Eclipse Temurin, macOS/aarch64) в .jdk/ в корне репозитория" >&2
    echo "  (--strip-components=3, см. CLAUDE.md), либо задайте JAVA_HOME на существующий JDK 21+." >&2
    exit 1
}
JLINK="$JDK_HOME/bin/jlink"
JPACKAGE="$JDK_HOME/bin/jpackage"
JDEPS="$JDK_HOME/bin/jdeps"

if [ ! -d "$JDK_HOME/jmods" ]; then
    echo "ошибка: $JDK_HOME/jmods не найден — нужен полный JDK (не JRE); портативный Temurin JDK его содержит" >&2
    exit 1
fi

for tool in codesign pkgbuild hdiutil sips iconutil; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ошибка: не найден '$tool' — нужны Xcode Command Line Tools (xcode-select --install)" >&2
        exit 1
    fi
done

"$REPO_ROOT/build.sh"
"$REPO_ROOT/build-gui.sh"

CORE_JAR="$REPO_ROOT/dist/eds-check.jar"
GUI_JAR="$REPO_ROOT/dist/eds-check-gui.jar"

GUI_VERSION_FILE="$REPO_ROOT/src/gui/java/kz/edscheck/gui/GuiVersion.java"
APP_VERSION="$(grep -o 'VALUE = "[^"]*"' "$GUI_VERSION_FILE" | sed -E 's/VALUE = "(.*)"/\1/')"
if [ -z "$APP_VERSION" ]; then
    echo "ошибка: не удалось извлечь версию из $GUI_VERSION_FILE" >&2
    exit 1
fi

RUNTIME_LIB_JARS="flatlaf-3.7.2-no-natives.jar pdfbox-3.0.7.jar pdfbox-io-3.0.7.jar commons-logging-1.4.0.jar"
FLATLAF_NATIVE="flatlaf-3.7.2-macos-arm64.dylib"

BUILD_DIR="$REPO_ROOT/build/gui/jpackage"
RUNTIME_DIR="$BUILD_DIR/runtime"
INPUT_DIR="$BUILD_DIR/input"
ICONSET_DIR="$BUILD_DIR/EDScheck.iconset"
ICNS_FILE="$BUILD_DIR/EDScheck.icns"
DIST_DIR="$REPO_ROOT/dist"

rm -rf "$RUNTIME_DIR" "$INPUT_DIR" "$ICONSET_DIR" "$ICNS_FILE"
mkdir -p "$INPUT_DIR" "$DIST_DIR"

MODULES="java.base,java.desktop,java.instrument,java.logging,java.net.http,jdk.crypto.ec"

CP_FOR_JDEPS=""
for name in $RUNTIME_LIB_JARS; do
    if [ -n "$CP_FOR_JDEPS" ]; then
        CP_FOR_JDEPS="$CP_FOR_JDEPS:$REPO_ROOT/lib/$name"
    else
        CP_FOR_JDEPS="$REPO_ROOT/lib/$name"
    fi
done
ACTUAL_MODULES="$("$JDEPS" --multi-release 21 --ignore-missing-deps --print-module-deps \
    --class-path "$CP_FOR_JDEPS" "$CORE_JAR" "$GUI_JAR")"
IFS=',' read -r -a actual_arr <<< "$ACTUAL_MODULES"
for m in "${actual_arr[@]}"; do
    case ",$MODULES," in
        *",$m,"*) ;;
        *)
            echo "ошибка: jdeps требует модуль '$m', отсутствующий в MODULES этого скрипта" >&2
            echo "  обновите переменную MODULES в build-gui-jpackage-mac.sh (см. комментарий выше)" >&2
            exit 1
            ;;
    esac
done

"$JLINK" \
    --module-path "$JDK_HOME/jmods" \
    --add-modules "$MODULES" \
    --strip-debug \
    --no-header-files \
    --no-man-pages \
    --output "$RUNTIME_DIR"

cp "$CORE_JAR" "$INPUT_DIR/"
cp "$GUI_JAR" "$INPUT_DIR/"
for name in $RUNTIME_LIB_JARS; do
    src="$REPO_ROOT/lib/$name"
    if [ ! -f "$src" ]; then
        echo "ошибка: ожидаемый рантайм-jar не найден: $src (версия сменилась? поправьте RUNTIME_LIB_JARS в этом скрипте)" >&2
        exit 1
    fi
    cp "$src" "$INPUT_DIR/"
done
FLATLAF_NATIVE_SRC="$REPO_ROOT/lib/$FLATLAF_NATIVE"
if [ ! -f "$FLATLAF_NATIVE_SRC" ]; then
    echo "ошибка: ожидаемая native-библиотека FlatLaf не найдена: $FLATLAF_NATIVE_SRC (версия сменилась? поправьте FLATLAF_NATIVE в этом скрипте)" >&2
    exit 1
fi
cp "$FLATLAF_NATIVE_SRC" "$INPUT_DIR/"
mkdir -p "$INPUT_DIR/certs"
cp "$REPO_ROOT/certs/MANIFEST.json" "$INPUT_DIR/certs/"
cp -R "$REPO_ROOT/certs/prod" "$INPUT_DIR/certs/prod"

ICON_PNG="$REPO_ROOT/src/gui/resources/kz/edscheck/gui/icon.png"
mkdir -p "$ICONSET_DIR"
for spec in "16:icon_16x16.png" "32:icon_16x16@2x.png" "32:icon_32x32.png" "64:icon_32x32@2x.png" \
            "128:icon_128x128.png" "256:icon_128x128@2x.png" "256:icon_256x256.png" \
            "512:icon_256x256@2x.png" "512:icon_512x512.png" "1024:icon_512x512@2x.png"; do
    size="${spec%%:*}"
    outname="${spec#*:}"
    sips -z "$size" "$size" "$ICON_PNG" --out "$ICONSET_DIR/$outname" >/dev/null
done
iconutil -c icns "$ICONSET_DIR" -o "$ICNS_FILE"

if [ "$PKG_TYPE" = "dmg" ]; then
    APP_STAGE_DIR="$BUILD_DIR/app-stage"
    rm -rf "$APP_STAGE_DIR"
    JPACKAGE_TYPE_ARG="app-image"
    JPACKAGE_DEST_ARG="$APP_STAGE_DIR"
else
    JPACKAGE_TYPE_ARG="$PKG_TYPE"
    JPACKAGE_DEST_ARG="$DIST_DIR"
fi

"$JPACKAGE" \
    --type "$JPACKAGE_TYPE_ARG" \
    --name EDScheck \
    --app-version "$APP_VERSION" \
    --input "$INPUT_DIR" \
    --dest "$JPACKAGE_DEST_ARG" \
    --main-jar "$(basename "$GUI_JAR")" \
    --main-class kz.edscheck.gui.GuiMain \
    --runtime-image "$RUNTIME_DIR" \
    --icon "$ICNS_FILE" \
    --mac-package-name EDScheck \
    --mac-package-identifier kz.edscheck.gui \
    --java-options '-Dkz.edscheck.libDir=$APPDIR' \
    --java-options '-Dkz.edscheck.certsDir=$APPDIR/certs' \
    --java-options '-Dflatlaf.nativeLibraryPath=$APPDIR' \
    --java-options '-javaagent:$APPDIR/eds-check-gui.jar'

if [ "$JPACKAGE_TYPE_ARG" = "app-image" ]; then
    APP_INFO_PLIST="$JPACKAGE_DEST_ARG/EDScheck.app/Contents/Info.plist"
    /usr/libexec/PlistBuddy -c "Add :LSHasLocalizedDisplayName bool true" "$APP_INFO_PLIST" 2>/dev/null \
        || /usr/libexec/PlistBuddy -c "Set :LSHasLocalizedDisplayName true" "$APP_INFO_PLIST"
    /usr/libexec/PlistBuddy -c "Add :CFBundleDisplayName string EDScheck" "$APP_INFO_PLIST" 2>/dev/null \
        || /usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName EDScheck" "$APP_INFO_PLIST"

    RESOURCES_DIR="$JPACKAGE_DEST_ARG/EDScheck.app/Contents/Resources"
    mkdir -p "$RESOURCES_DIR/ru.lproj"
    printf '"CFBundleName" = "Проверка ЭЦП";\n"CFBundleDisplayName" = "Проверка ЭЦП";\n' > "$RESOURCES_DIR/ru.lproj/InfoPlist.strings"

    codesign --force --deep -s - "$JPACKAGE_DEST_ARG/EDScheck.app"
fi

FINAL_ARTIFACT="$DIST_DIR/EDScheck.app"

if [ "$PKG_TYPE" = "dmg" ]; then
    "$JPACKAGE" \
        --type dmg \
        --name EDScheck \
        --app-version "$APP_VERSION" \
        --app-image "$APP_STAGE_DIR/EDScheck.app" \
        --dest "$DIST_DIR" \
        --icon "$ICNS_FILE" \
        --mac-package-name EDScheck \
        --mac-package-identifier kz.edscheck.gui
    rm -rf "$APP_STAGE_DIR"
    FINAL_ARTIFACT="$DIST_DIR/EDScheck-$APP_VERSION.dmg"
elif [ "$PKG_TYPE" = "pkg" ]; then
    FINAL_ARTIFACT="$DIST_DIR/EDScheck-$APP_VERSION.pkg"
fi

echo
echo "готово: $FINAL_ARTIFACT (тип: $PKG_TYPE)"
