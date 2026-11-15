#!/usr/bin/env sh
# Compiles NetScan into build/netscan.jar using only the JDK (no Maven/Gradle needed).
set -e
cd "$(dirname "$0")"

rm -rf build
mkdir -p build/classes
javac -d build/classes $(find src/main/java -name '*.java')
cp -R src/main/resources/. build/classes/
jar --create --file build/netscan.jar --main-class netscan.NetScanServer -C build/classes .

echo "Built build/netscan.jar  ->  run with:  java -jar build/netscan.jar"
