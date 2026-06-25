# Endpoint Security provisioning & signing setup

How `macos-endptsec101` binaries get the runtime authority to call `es_new_client()`.
This is the exact, working procedure used on 2026-06-25 after Apple granted the
managed Endpoint Security entitlement.

## Why this is needed

`com.apple.developer.endpoint-security.client` is a **managed entitlement**. Three
things must all be true at runtime or `es_new_client()` fails:

1. The binary is **code-signed** with a certificate from your team.
2. An **embedded provisioning profile** authorizes the ES entitlement for that
   binary's bundle id + this machine.
3. The binary is signed with the **hardened runtime** (`--options runtime`).

Plus, at run time: **root** (`sudo`) and **Full Disk Access** on the calling terminal.

CLI binaries have nowhere to embed a profile, so each one is wrapped in a minimal
`.app` bundle (`Contents/embedded.provisionprofile`).

## Prerequisites (already true for this project)

- Apple Developer Program membership (active).
- The ES entitlement **granted** to the account (request `XX88K38278`, granted
  2026-06-24). Renewing membership alone does NOT grant it — it is requested
  separately at developer.apple.com → "Request a System Extension or DriverKit
  Entitlement", and Apple replies by email.
- A signing identity in the login keychain:
  `Apple Development: Douglas Mun (PABRCU3Y4G)`, Team `84F6C3L9WG`
  (`security find-identity -v -p codesigning` shows it).

## The one hard-won lesson: EXPLICIT App ID, not wildcard

> **Endpoint Security cannot be enabled on a wildcard App ID.**

The portal will *silently uncheck* the Endpoint Security capability the moment the
bundle id is a wildcard (`com.douglasmun.endptsec.*`). The generated profile then
comes back **without** `com.apple.developer.endpoint-security.client`, and every
binary fails at runtime with `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`.

The fix is an **explicit** App ID: `com.douglasmun.endptsec`. Because the 16 chapter
binaries are only ever run **one at a time** (never installed side-by-side, never
distributed), they can all share that single explicit bundle id. One App ID, one
profile, all 16 chapters.

## Portal steps (developer.apple.com → Certificates, Identifiers & Profiles)

### 0. Certificate — nothing to do

You already have `Apple Development: Douglas Mun` in your keychain *with* its private
key (that's why `find-identity` lists it). Do **not** create a new "Mac Development"
certificate — it produces the same identity and a fresh private key to manage. Skip
the Certificates page entirely.

### 1. Register this Mac as a device

A Mac Development profile requires at least one registered device.

- Get this Mac's **Provisioning UDID** (NOT the Hardware UUID, NOT the serial):

  ```sh
  /usr/sbin/system_profiler SPHardwareDataType | grep 'Provisioning UDID'
  # ApolloM5Max -> 00006050-001158CC116B401C
  ```

- Devices → ➕ → Platform **macOS** → Device Name `ApolloM5Max` →
  Device ID (UDID) = the Provisioning UDID above → Continue → Register.

### 2. Create the EXPLICIT App ID

- Identifiers → ➕ → **App IDs** → **App** → Continue.
- Description: `macOS Endpoint Security 101`.
- Bundle ID: select **Explicit** (NOT Wildcard) → `com.douglasmun.endptsec`.
- Capabilities: scroll to **Endpoint Security** and check it ☑️.
  (It is only checkable because the App ID is explicit. On a wildcard it is greyed /
  silently unchecks.)
- Continue → Register.

### 3. Create the provisioning profile

- Profiles → ➕ → **macOS App Development** → Continue.
- App ID: select `com.douglasmun.endptsec` (the explicit one).
- Certificate: check `Apple Development: Douglas Mun`.
- Devices: check `ApolloM5Max`.
- Profile Name: `endptsec-dev`.
- Generate → Download.

Profiles are immutable snapshots: if you change the App ID's capabilities later, you
must **regenerate and re-download** the profile.

### 4. Verify the downloaded profile actually carries ES

Before signing, confirm the entitlement made it in (this caught two bad profiles
that lacked ES because the App ID was wildcard / had the wrong capability checked):

```sh
PROF=~/Downloads/endptsecdev.provisionprofile
security cms -D -i "$PROF" > /tmp/es_prof.plist
/usr/libexec/PlistBuddy -c "Print :Entitlements:com.apple.application-identifier" /tmp/es_prof.plist
#   -> 84F6C3L9WG.com.douglasmun.endptsec
/usr/libexec/PlistBuddy -c "Print :Entitlements:com.apple.developer.endpoint-security.client" /tmp/es_prof.plist
#   -> true        (if this errors / prints nothing, the profile is bad — fix the App ID and regenerate)
/usr/libexec/PlistBuddy -c "Print :ProvisionedDevices" /tmp/es_prof.plist
#   -> 00006050-001158CC116B401C
```

## Build & sign all 16 chapters

The root `Makefile` + `tools/package.sh` automate wrap → embed profile → sign.

```sh
cd macos-endptsec101
make sign PROFILE=~/Downloads/endptsecdev.provisionprofile
```

What `tools/package.sh` does per chapter:

1. Compile the CLI (via the chapter's own Makefile).
2. Create `NN-dir/<target>.app/Contents/MacOS/<target>` + a minimal `Info.plist`
   whose `CFBundleIdentifier` is the explicit `com.douglasmun.endptsec`.
3. Copy the profile to `Contents/embedded.provisionprofile`.
4. `codesign --force --options runtime --timestamp --entitlements <chapter>.entitlements
   --sign "Apple Development: Douglas Mun (PABRCU3Y4G)"` on the inner exe, then the bundle.

`APP_ID` defaults to `com.douglasmun.endptsec`; override with `make sign APP_ID=...`
only if you regenerate the profile against a different explicit App ID.

Note: ch11's target is `codesign-monitor` (not `codesign`); the tooling reads the
real `TARGET` from each chapter's Makefile, so this is handled automatically.

## Verify the signatures (run in your own terminal, not via tooling)

```sh
for ch in [0-9]*/; do
  tgt=$(grep -E '^TARGET' "$ch/Makefile" | head -1 | sed 's/.*=[[:space:]]*//' | tr -d ' ')
  exe="$ch$tgt.app/Contents/MacOS/$tgt"
  es=$(codesign -d --entitlements - "$exe" 2>/dev/null | grep -c endpoint-security)
  rt=$(codesign -dvv "$exe" 2>&1 | grep -c 'flags=.*runtime')
  printf "%-18s ES=%s runtime=%s  %s\n" "$tgt" "$es" "$rt" \
    "$(codesign --verify --strict "$exe" 2>&1 && echo ok || echo FAIL)"
done
```

Healthy line: `hello-exec  ES=1 runtime=1  ok`.

## Run

```sh
# Grant Full Disk Access to your terminal first:
#   System Settings → Privacy & Security → Full Disk Access → add Terminal/iTerm → ON
#   then fully quit (⌘Q) and reopen the terminal.

sudo ./01-hello-exec/hello-exec.app/Contents/MacOS/hello-exec
# Ctrl-C to stop.
```

Failure → meaning:

| Symptom | Cause |
|---|---|
| `...ERR_NOT_ENTITLED` | profile missing ES (wildcard App ID) — regenerate explicit |
| `...ERR_NOT_PRIVILEGED` | not running under `sudo` |
| `...ERR_NOT_PERMITTED` / "grant Full Disk Access" | terminal lacks Full Disk Access (grant + relaunch terminal) |

## Notes & maintenance

- The working profile `endptsec-dev` expires **2027-06-25**. Regenerate before then.
- Adding another Mac: register its Provisioning UDID, regenerate the profile, re-`make sign`.
- `codesign -d` / `--verify` and ES runtime **cannot** be exercised from inside the
  Claude Code Bash sandbox (seatbelt returns "host has no guest" / "No such process").
  Run verification and `sudo` runtime tests directly in a real terminal.
