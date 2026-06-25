#!/bin/bash
#
# package.sh — wrap a compiled ES CLI binary into a minimal signed .app bundle
#              with an embedded provisioning profile and hardened runtime.
#
# Why a .app: a provisioning profile can only be embedded in a bundle
# (Contents/embedded.provisionprofile). The ES entitlement is "managed" and
# only honored at runtime when the profile authorizing it is embedded and the
# code is signed with the hardened runtime (--options runtime).
#
# Usage: package.sh <chapter-dir> <target-name> <entitlements-file>
# Env:
#   SIGN_ID   signing identity (default: Apple Development: Douglas Mun (PABRCU3Y4G))
#   PROFILE   path to .provisionprofile with the ES capability (required)
#   APP_ID    explicit bundle id — MUST match the explicit App ID the profile was
#             generated for (default: com.douglasmun.endptsec). Endpoint Security
#             is not allowed on wildcard App IDs, so every bundle shares this one
#             explicit id. They are only ever run one at a time.
#
set -euo pipefail

CHDIR="$1"; TARGET="$2"; ENT="$3"
SIGN_ID="${SIGN_ID:-Apple Development: Douglas Mun (PABRCU3Y4G)}"
APP_ID="${APP_ID:-com.douglasmun.endptsec}"
PROFILE="${PROFILE:-}"

if [[ -z "$PROFILE" || ! -f "$PROFILE" ]]; then
  echo "ERROR: PROFILE env must point to the .provisionprofile (ES capability)." >&2
  echo "       Download it from developer.apple.com and pass PROFILE=/path." >&2
  exit 2
fi

BIN="$CHDIR/$TARGET"
[[ -f "$BIN" ]] || { echo "ERROR: binary not found: $BIN (run make first)" >&2; exit 2; }

APP="$CHDIR/$TARGET.app"
MACOS="$APP/Contents/MacOS"
BUNDLE_ID="$APP_ID"

rm -rf "$APP"
mkdir -p "$MACOS"
cp "$BIN" "$MACOS/$TARGET"
cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key><string>$TARGET</string>
    <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
    <key>CFBundleName</key><string>$TARGET</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>LSBackgroundOnly</key><true/>
</dict>
</plist>
PLIST

# Sign the inner executable, then the bundle, with the chapter entitlements +
# hardened runtime. The entitlements file must request the ES client entitlement.
codesign --force --options runtime --timestamp \
         --entitlements "$ENT" \
         --sign "$SIGN_ID" \
         "$MACOS/$TARGET"

codesign --force --options runtime --timestamp \
         --entitlements "$ENT" \
         --sign "$SIGN_ID" \
         "$APP"

echo "built  $APP  ($BUNDLE_ID)"
