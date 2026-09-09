#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
checks_dir=$(mktemp -d)
trap 'rm -rf "$checks_dir"' EXIT
javac -d "$checks_dir" app/src/main/java/com/vlightsoft/passkeyx/NativePolicy.java app/src/main/java/com/vlightsoft/passkeyx/ExpiringRequests.java tests/NativeCoreCheck.java
java -cp "$checks_dir" com.vlightsoft.passkeyx.NativeCoreCheck
