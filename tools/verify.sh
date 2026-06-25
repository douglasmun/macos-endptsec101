#!/bin/bash
# verify.sh — confirm a signed .app has the ES entitlement and embedded profile.
# Usage: verify.sh <chapter-dir> <target-name>
set -euo pipefail
CHDIR="$1"; TARGET="$2"
APP="$CHDIR/$TARGET.app"
EXE="$APP/Contents/MacOS/$TARGET"
[[ -d "$APP" ]] || { echo "MISSING bundle: $APP" >&2; exit 1; }

echo "== $TARGET =="
codesign --verify --strict --verbose=2 "$APP" 2>&1 | sed 's/^/  /'
ent=$(codesign -d --entitlements - --xml "$EXE" 2>/dev/null \
      | grep -c "com.apple.developer.endpoint-security.client" || true)
[[ "$ent" -ge 1 ]] && echo "  OK  ES entitlement present" || echo "  FAIL no ES entitlement"
runtime=$(codesign -d --verbose=2 "$EXE" 2>&1 | grep -c "runtime" || true)
[[ "$runtime" -ge 1 ]] && echo "  OK  hardened runtime" || echo "  WARN no hardened runtime flag"
[[ -f "$APP/Contents/embedded.provisionprofile" ]] \
  && echo "  OK  embedded profile" || echo "  FAIL no embedded profile"
