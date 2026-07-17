#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$DIR"

resolve_jdk_bin() {
    if [ -x "$REPO_ROOT/.jdk/bin/javac" ]; then
        echo "$REPO_ROOT/.jdk/bin"
        return 0
    fi
    if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/javac" ]; then
        echo "$JAVA_HOME/bin"
        return 0
    fi
    if command -v javac >/dev/null 2>&1; then
        dirname "$(command -v javac)"
        return 0
    fi
    return 1
}

JDK_BIN="$(resolve_jdk_bin)" || {
    echo "ошибка: не найден JDK (проверены .jdk/bin, \$JAVA_HOME/bin, PATH)" >&2
    echo "  распакуйте портативный JDK 21 (Eclipse Temurin) в .jdk/ в корне репозитория," >&2
    echo "  либо задайте JAVA_HOME на существующий JDK 21+." >&2
    exit 1
}
JAVAC="$JDK_BIN/javac"
JAR_TOOL="$JDK_BIN/jar"

CORE_JAR="$DIR/dist/eds-check.jar"
if [ ! -f "$CORE_JAR" ]; then
    echo "ошибка: не найден $CORE_JAR" >&2
    echo "  сначала соберите ядро: ./build.sh" >&2
    exit 1
fi

SRC_DIR="$DIR/src/gui/java"
BUILD_DIR="$DIR/build/gui/classes"
DIST_DIR="$DIR/dist"
LIB_DIR="$DIR/lib"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$DIST_DIR"

SOURCES=()
while IFS= read -r f; do
    SOURCES+=("$f")
done < <(find "$SRC_DIR" -name '*.java' | sort)
if [ "${#SOURCES[@]}" -eq 0 ]; then
    echo "ошибка: нет исходников в $SRC_DIR" >&2
    exit 1
fi

KALKAN_JAR="$REPO_ROOT/lib/kalkancrypt-0.7.6-certified.jar"
CP="$CORE_JAR:$KALKAN_JAR"
shopt -s nullglob
LIB_JARS=("$LIB_DIR"/*.jar)
shopt -u nullglob
if [ "${#LIB_JARS[@]}" -gt 0 ]; then
    CP="$CP:$(IFS=:; echo "${LIB_JARS[*]}")"
fi

"$JAVAC" -cp "$CP" -d "$BUILD_DIR" "${SOURCES[@]}"

RES_DIR="$DIR/src/gui/resources"
if [ -d "$RES_DIR" ]; then
    cp -R "$RES_DIR/." "$BUILD_DIR/"
fi

"$JAR_TOOL" --create --file "$DIST_DIR/eds-check-gui.jar" \
    --main-class kz.edscheck.gui.GuiMain \
    -C "$BUILD_DIR" .

echo "собрано: $DIST_DIR/eds-check-gui.jar (запуск — bin/EDScheck, classpath включает dist/eds-check.jar)"
