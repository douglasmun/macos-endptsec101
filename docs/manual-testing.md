# Manual testing guide

How to run and trigger each chapter by hand. Every chapter is a long-running ES
client: it prints a banner, then events as they arrive. Stop with **Ctrl-C**.

## Prerequisites (once)

1. **Build + sign all** (ES entitlement granted; profile `endptsec-dev`):
   ```sh
   make sign PROFILE="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles/431f14a5-a83a-4621-a441-ea8fbcdb029a.provisionprofile"
   ```
   (Find the right file with: `ls ~/Library/Developer/Xcode/UserData/Provisioning\ Profiles/` and decode names via
   `security cms -D -i <file> | plutil -extract Name raw -`.)

2. **Full Disk Access** for your terminal: System Settings → Privacy & Security →
   Full Disk Access → enable Terminal/iTerm. Without it `es_new_client` returns
   `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`.

3. Run as **root**. The binary lives inside the `.app`:
   ```sh
   sudo ./01-hello-exec/hello-exec.app/Contents/MacOS/hello-exec
   ```

If `es_new_client` fails:
- `ERR_NOT_PRIVILEGED` → you forgot `sudo`.
- `ERR_NOT_PERMITTED` → terminal lacks Full Disk Access.
- `ERR_NOT_ENTITLED` → signature/profile problem; re-run `make sign` and `make verify`.

Each test: open **two** terminals — one runs the monitor (left), the other runs
the trigger (right).

---

## 01 — hello-exec  (NOTIFY_EXEC/FORK/EXIT)
Run:  `sudo ./01-hello-exec/hello-exec.app/Contents/MacOS/hello-exec`
Trigger (other terminal): `ls /` , or any command.
Expect: an `EXEC` line for `/bin/ls` with pid, then `FORK`/`EXIT` lines as
processes come and go.

## 02 — file-monitor  (NOTIFY_CREATE/WRITE/UNLINK/RENAME)
Run:  `sudo ./02-file-monitor/file-monitor.app/Contents/MacOS/file-monitor`
Trigger:
```sh
echo hi > /tmp/estest.txt        # CREATE + WRITE
mv /tmp/estest.txt /tmp/est2.txt # RENAME
rm /tmp/est2.txt                 # UNLINK
```
Expect: CREATE, WRITE, RENAME, UNLINK lines with the paths.

## 03 — auth-exec  (AUTH_EXEC — block before exec)
Run:  `sudo ./03-auth-exec/auth-exec.app/Contents/MacOS/auth-exec`
Policy: denies by **leaf filename** — deny list is `nc`, `ncat` — and only for
**non-platform** binaries. Full path is irrelevant; a platform binary named `nc`
is still allowed.
Trigger:
```sh
cp /bin/cat /tmp/nc && /tmp/nc < /dev/null   # DENY — leaf name "nc", non-platform
ls /                                          # ALLOW — any other command
```
Expect: `[ALLOW]` for normal commands; `[DENY]` for `/tmp/nc` (shell reports the
exec was blocked). `/tmp/nc` is a copy of `cat`, so it carries an ad-hoc
signature and actually reaches AUTH_EXEC.

## 04 — network  (NOTIFY_UIPC_CONNECT)
Run:  `sudo ./04-network/network.app/Contents/MacOS/network`
Trigger: anything that connects a **Unix domain socket** (AF_UNIX). Note: this
event does NOT carry remote IP for TCP — only Unix socket path. Many daemons
connect AF_UNIX constantly, so you should see events immediately on launch.
Expect: UIPC_CONNECT lines with domain/type/protocol and the socket path.

## 05 — muting  (es_mute_path + invert)
Run:  `sudo ./05-muting/muting.app/Contents/MacOS/muting`
Behavior: path-muting table is INVERTED → allowlist mode. After startup, only
NOTIFY_EXEC for binaries **under `/usr/bin` (prefix)** or **exactly
`/usr/sbin/dtrace` (literal)** are reported; every other exec is suppressed.
(Self-mute uses the separate process table and is unaffected by path inversion.)
Trigger:
```sh
/usr/bin/uptime            # REPORTED → [EXEC] ... path=/usr/bin/uptime
/bin/echo hi               # suppressed (not under /usr/bin)
ls /                       # /bin/ls → suppressed
```
Expect: `[EXEC]` lines only for `/usr/bin/*` execs; everything else silent.

## 06 — lsm-analog  (multi-AUTH policy engine)
Run:  `sudo ./06-lsm-analog/lsm-analog.app/Contents/MacOS/lsm-analog`
Policy:
- **AUTH_EXEC**: non-platform binary ALLOWED only if its `team_id` is in the
  allowlist (`PABRCU3Y4G`). No team_id / other team → DENY.
- **AUTH_CREATE / AUTH_UNLINK**: DENIED for **non-platform** processes acting
  under protected prefixes `/etc`, `/Library/LaunchDaemons`,
  `/Library/LaunchAgents`, `/System`. Only protected-path events are logged.
  NOTE: the verdict keys on the **acting process**, not the file. `touch`,
  `rm`, `cp` are platform binaries → their creates/unlinks are ALLOWED. You
  must use a **non-platform** writer to see a DENY.
Trigger:
```sh
# exec deny — copy of cat has an ad-hoc sig and no team_id
cp /bin/cat /tmp/notrust && /tmp/notrust < /dev/null      # [EXEC:DENY]

# create deny — need a NON-platform process creating under /etc.
# /tmp/notrust is non-platform; have it create a file via shell redirection
# won't work (shell is platform). Compile a tiny creator instead:
printf 'int main(){return open("/etc/estest",0x601,0644);}' > /tmp/mk.c
echo '#include <fcntl.h>' | cat - /tmp/mk.c > /tmp/mk2.c && cc -o /tmp/mkfile /tmp/mk2.c
sudo /tmp/mkfile                                          # [CREATE:DENY] /etc/estest
```
Expect: `[EXEC:DENY]` for `/tmp/notrust`; `[CREATE:DENY ]` for the /etc create by
the non-platform `/tmp/mkfile`. Platform binaries pass silently.

## 07 — ids  (stateful: EXEC + WRITE + UIPC_CONNECT)
Run:  `sudo ./07-ids/ids.app/Contents/MacOS/ids`
Trigger RULE-2 (write /tmp then AF_UNIX connect — the canonical PoC):
```sh
cc -o /tmp/ids-poc tools/ids-poc.c && /tmp/ids-poc
```
Expect: a JSON alert when one process both writes /tmp and opens a Unix socket.

## 08 — ancestry  (FORK + EXEC + EXIT, process tree)
Run:  `sudo ./08-ancestry/ancestry.app/Contents/MacOS/ancestry`
Trigger: spawn a child chain, ideally a "download tool" under a shell:
```sh
bash -c 'curl --version'      # curl with bash ancestry
```
Expect: EXEC lines annotated with the ancestry chain (parent → grandparent …).
The suspicious-ancestry rule fires for download tools under browser ancestors.

## 09 — tcc  (NOTIFY_AUTHORIZATION_JUDGEMENT)
Run:  `sudo ./09-tcc/tcc.app/Contents/MacOS/tcc`
Trigger: cause a privacy permission judgement — e.g. open an app that requests
Camera/Microphone/Screen Recording, or toggle a permission in System Settings →
Privacy & Security. TCC right names arrive prefixed `com.apple.TCC.`.
Expect: judgement lines naming the service (Microphone, Camera, …) and verdict.

## 10 — persistence  (BTM_LAUNCH_ITEM_ADD/REMOVE)
Run:  `sudo ./10-persistence/persistence.app/Contents/MacOS/persistence`
Trigger: register a LaunchAgent (goes through BTM):
```sh
cat > ~/Library/LaunchAgents/com.test.estest.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.test.estest</string>
  <key>ProgramArguments</key><array><string>/bin/echo</string><string>hi</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
EOF
launchctl load ~/Library/LaunchAgents/com.test.estest.plist     # BTM-ADD
launchctl unload ~/Library/LaunchAgents/com.test.estest.plist   # BTM-REMOVE
rm ~/Library/LaunchAgents/com.test.estest.plist
```
Expect: `[BTM-ADD]` line (and an unsigned-persistence ALERT, since your shell is
non-platform with no team id); `[BTM-REMOVE]` on unload; an execute-once-cleanup
ALERT if add→remove happens within 60 s.

## 11 — codesign  (AUTH_EXEC + codesigning flags)
Run:  `sudo ./11-codesign/codesign-monitor.app/Contents/MacOS/codesign-monitor`
Policy (IMPORTANT — the cdhash allowlist is EMPTY; default is ALLOW to avoid
lockout). Only two rules actually DENY, both for non-platform binaries:
- **CS_DEBUGGED set** → DENY (code integrity may be disabled).
- under **/usr/bin/ or /usr/sbin/ without CS_HARD** → DENY.
Every exec prints an `[EXEC] ... cdhash=<40-hex>` line regardless of verdict.
Trigger:
```sh
ls /                       # [EXEC] line, ALLOWED (just observe the cdhash output)

# Rule 2 (CS_DEBUGGED) — run a non-platform binary under a debugger:
cp /bin/cat /tmp/dbgtest
sudo lldb -o run -o quit -- /tmp/dbgtest < /dev/null   # → [ALERT] CS_DEBUGGED ... DENY
```
Expect: normal execs logged + allowed; the debugged process denied with an
`[ALERT] CS_DEBUGGED` line. (To exercise the allowlist, add a real cdhash to
`g_allowlist` in codesign.c and rebuild — by default it changes nothing.)

## 12 — dynamic-policy  (live mute + config file watch)
Run:  `sudo ./12-dynamic-policy/dynamic-policy.app/Contents/MacOS/dynamic-policy`
Config: HARDCODED path
`/Users/douglasmun/Develop/macos-endptsec101/12-dynamic-policy/policy.conf`.
Each non-comment line is an **AUTH_EXEC mute prefix**: execs whose path matches
a muted prefix are allowed **silently** (no `[EXEC] allow` log); all others log.
The monitor watches NOTIFY_WRITE on the config path and reloads on change.
Two gotchas:
- The reload only fires when the write's full untruncated path == CONFIG_PATH.
  vim/editors that save via temp-file+rename WON'T trigger it. Use an in-place
  append: `echo '/private/tmp' >> .../policy.conf`.
- A muted prefix SUPPRESSES the log line — that absence is the observable effect.
Trigger:
```sh
# baseline: run something from /tmp and see it logged
cp /bin/cat /tmp/probe && /tmp/probe < /dev/null    # → [EXEC] allow path=/private/tmp/probe

# now mute /private/tmp live (in-place append triggers reload)
echo '/private/tmp' >> /Users/douglasmun/Develop/macos-endptsec101/12-dynamic-policy/policy.conf
# monitor prints: [CONFIG] reloaded N paths
/tmp/probe < /dev/null                               # → NO log line (muted)

# remove it to unmute
# (edit the file back to drop the /private/tmp line, in place)
```
Expect: `[CONFIG] reloaded` after each in-place edit; the `[EXEC] allow` line for
`/private/tmp/probe` present before muting and absent after.

## 13 — auth-open  (AUTH_OPEN + fflag)
Run:  `sudo ./13-auth-open/auth-open.app/Contents/MacOS/auth-open`
Policy: only **write** opens (FWRITE bit) by **non-platform** processes on an
exact-match guarded path are evaluated. Reads are always allowed; platform
binaries (vi, nano, sh, cp as /bin/cp) are fast-allowed. Guarded paths:
`/etc/hosts`, `/etc/sudoers`, `/etc/pam.d/sudo` (+ their `/private/etc/...`
forms — the kernel resolves `/etc` → `/private/etc`),
`/Library/Application Support/com.apple.TCC/TCC.db`, `/private/var/db/auth.db`.
Trigger (need a non-platform binary doing a write open):
```sh
cp /bin/cp /tmp/mywriter                 # non-platform copy (ad-hoc sig, no team_id)
echo "127.0.0.1 estest" > /tmp/x
sudo /tmp/mywriter /tmp/x /etc/hosts     # write open of /etc/hosts → DENY
```
Expect: `[OPEN] ... file=/private/etc/hosts ...` then
`[ALERT] unsigned-sensitive-write` and the copy fails (DENY). A plain
`vi /etc/hosts` will NOT trip it (vi is a platform binary).

## 14 — cs-invalidated  (NOTIFY_CS_INVALIDATED)
Run:  `sudo ./14-cs-invalidated/cs-invalidated.app/Contents/MacOS/cs-invalidated`
Trigger: cause a running signed process to have its code signature invalidated
(runtime code injection / self-modification). Hard to do safely; may only fire
under real tampering. Document if no benign trigger exists.
Expect: a CS_INVALIDATED line for the affected process when it occurs.

## 15 — deferred-auth  (es_retain_message + deadline-aware AUTH)
Run:  `sudo ./15-deferred-auth/deferred-auth.app/Contents/MacOS/deferred-auth`
Trigger: same exec triggers as ch03/ch11 — the difference is the verdict is
computed on a background queue and responded before the deadline:
```sh
cp /bin/echo /tmp/echo && /tmp/echo hi
```
Expect: exec briefly stalls (deferred evaluation) then ALLOW/DENY; no kernel
deadline misses.

## 16 — unified-agent  (capstone — all subsystems on one client)
Run:  `sudo ./16-unified-agent/unified-agent.app/Contents/MacOS/unified-agent`
Subscribes to FORK/EXEC/EXIT, WRITE, UIPC_CONNECT, AUTHORIZATION_JUDGEMENT,
BTM ADD/REMOVE, CS_INVALIDATED, AUTH_EXEC, AUTH_OPEN. NOTE: rules are
INDEPENDENT — there is no cross-signal scoring/convergence. Each fires on its
own. Thresholds and triggers:
- **exec-chain**: >5 execs by one proc within 10 s → `rule=exec-chain`.
  `for i in $(seq 1 8); do /bin/echo $i >/dev/null; done` from one shell.
- **sensitive-file-write**: a proc writes under `/private/tmp` then exec's →
  `rule=sensitive-file-write`. `sh -c 'echo x >/tmp/z; exec /bin/date'`.
- **fanout**: >10 INET connects by one proc within 30 s → `rule=fanout`.
- **AUTH_EXEC DENY**: non-platform binary that is cs_invalidated OR CS_DEBUGGED.
  `cp /bin/cat /tmp/d; sudo lldb -o run -o quit -- /tmp/d </dev/null`.
- **AUTH_OPEN DENY**: non-platform proc with NO team_id, write-opening a
  sensitive path (`/etc/hosts`, `/etc/sudoers`, TCC.db, `/private/var/db/auth.db`,
  + `/private/etc` forms). `cp /bin/cp /tmp/w; sudo /tmp/w /tmp/x /etc/hosts`.
- **TCC sensitive**: non-platform proc granted Microphone/Camera/ScreenCapture/
  SystemPolicyAllFiles → `[ALERT] TCC sensitive`. Grant one in System Settings.
- **BTM persistence**: non-platform + no-team_id registrar adds a launch item →
  `[ALERT] BTM persistence`. Use the ch10 LaunchAgent load snippet.
- **CS_INVALIDATED**: any process whose signature is invalidated at runtime.
Expect: `[EXEC]/[AUTH-EXEC]/[AUTH-OPEN]/[BTM-ADD]/[AUTH-JUDGEMENT]` lines plus
the per-rule `[ALERT]` lines above. On Ctrl-C it `dispatch_barrier_sync`s the
work queue (drains in-flight deferred AUTH) and prints `evals=/deadline-misses=`.

---

## Notes
- The Bash sandbox used during development cannot run these (ES clients need
  real root + unsandboxed Security framework). Always run from your own terminal.
- For exec-deny chapters on Apple Silicon: a fully-unsigned binary is killed by
  the OS before ES sees it. Use `cp /bin/echo /tmp/echo` (carries an ad-hoc
  signature) so the binary actually reaches AUTH_EXEC.
- Clean up test artifacts (/tmp files, LaunchAgents) after each run.
