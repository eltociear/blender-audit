# blender-audit

**Scan Blender add-ons, extensions and `.blend` files for malicious patterns before you enable or open them.**
Zero dependencies, one file, MIT. Nothing is imported, enabled, opened in Blender or executed: sources
are parsed with Python's own `ast`, `.blend` files are read as bytes.

```bash
python blender_audit.py some_addon.zip                 # a downloaded add-on / extension
python blender_audit.py --extensions looptools         # straight from extensions.blender.org
python blender_audit.py --github owner/repo            # a GitHub add-on (tarball, text sources only)
python blender_audit.py --installed                    # everything in your Blender user folders
python blender_audit.py character.blend                # Python embedded in a .blend
```

## Why this exists

An enabled add-on is plain Python with your user's full privileges. Its module body and `register()`
run **every time Blender starts**, its app handlers fire on **every file load, save and frame change**,
and nothing sandboxes any of it. `.blend` files can carry Python too: Text datablocks registered as
modules and driver expressions run as soon as *Auto Run Python Scripts* is on.

That second path is not theoretical. In November 2025 Morphisec reported a campaign that uploaded free
3D models to marketplaces such as CGTrader with a weaponized `Rig_Ui.py` in the `.blend`'s
`bpy.data.texts`. With Auto Run enabled, the script fetched a loader from a Cloudflare Workers URL and
the chain ended in the StealC V2 infostealer
([Morphisec, 24 Nov 2025](https://www.morphisec.com/blog/morphisec-thwarts-russian-linked-stealc-v2-campaign-targeting-blender-users-via-malicious-blend-files/)).
`tests/run.py` builds an inert `.blend` with exactly that shape, and `blender-audit` flags it.

## What it looks for, and when it runs

Every finding is tagged with **when** the code runs, because that decides how much it matters:

| when | meaning |
| --- | --- |
| `import` / `register` | module body, `register()` and whatever it calls: runs on enable **and every Blender start** |
| `handler` | functions hooked into `bpy.app.handlers` / `bpy.app.timers` / `msgbus`, or `@persistent`: run on load / save / depsgraph / frame events |
| `runtime` | operators, panels, other functions: run when the user clicks something |
| `unloaded` | tests, docs, build scripts outside the add-on package: downgraded |
| `blend` | Python embedded in a `.blend` |

**23 scored patterns** (6 CRITICAL, 9 HIGH, 6 MEDIUM, 2 LOW) plus 11 informational context records that never touch the score:

| Pattern | Severity (strongest) | What it means |
| --- | --- | --- |
| Decode-then-Execute (`decode_exec`) | CRITICAL | exec/eval/compile of base64/zlib/marshal/hex-decoded data |
| Reverse Shell (`reverse_shell`) | CRITICAL | socket wired to a shell (dup2 / pty.spawn / stdin=socket) |
| Credential Exfiltration (`credential_exfil`) | CRITICAL | reads a token / browser / wallet store and sends data off-host |
| Environment Exfiltration (`env_exfil`) | CRITICAL | serialises os.environ and sends it |
| Persistence Write (`persistence_write`) | CRITICAL | writes shell rc / authorized_keys / crontab / LaunchAgents / sitecustomize |
| Download & Execute (`download_execute`) | CRITICAL | fetches a URL and runs it (curl\|sh, exec(requests.get().text)) |
| Blender Startup Persistence (`startup_persist`) | HIGH | writes into Blender's scripts/startup folder (runs on every launch, outside the add-on) |
| Auto Run Enabled from Code (`auto_exec_enable`) | HIGH | sets use_scripts_auto_execute = True: every .blend's embedded scripts then run |
| Handler Runs .blend Text (`blend_autorun`) | HIGH | an app handler exec()s Text datablocks of loaded files, bypassing Auto Run |
| Collector Endpoint (`exfil_host`) | HIGH | hard-coded webhook / bot / tunnel / OAST host |
| Shell Execution (`shell_exec`) | HIGH | os.system / shell=True with a command built at runtime, or exec at enable time |
| Dynamic Code Execution (`dynamic_exec`) | MEDIUM | exec / eval / compile of an opaque (non-literal, non-template) value at enable time |
| Obfuscated Code (`obfuscation`) | HIGH | __import__('os'...) chains, getattr(builtins,'exec'), split-literal hosts with a send |
| Runtime pip install (`pip_install`) | HIGH | installs packages from code (HIGH from URL/git at enable time; MEDIUM at enable; LOW in an operator) |
| Shadow Wheel (`shadow_wheel`) | HIGH | pure-Python package pinned to a direct URL off PyPI |
| Known-Malicious Release (`known_bad_version`) | HIGH | pins a release publicly known to be malicious |
| Network at Enable Time (`import_network`) | MEDIUM | network call to a non-Blender host at import / register |
| Raw-IP Endpoint (`raw_ip`) | MEDIUM | network call to a public raw IP address |
| Custom Package Index (`custom_index`) | MEDIUM | installs from a non-standard package index |
| Possible Typosquat (`typosquat`) | MEDIUM | dependency / wheel one edit away from a popular package |
| Code in .blend (`blend_payload`) | MEDIUM | a malicious shape inside a .blend's embedded Python (runs once Auto Run is on) |
| Undeclared Network Permission (`undeclared_network`) | LOW | extension uses the network but blender_manifest.toml has no network permission |
| Secret Env Read (`secret_env_read`) | LOW | reads another service's credential env var |

Informational (score 0): `process_exec`, `network`, `blend_script`, `blend_compressed`, `run_text`, `addon_install`, `wheel_bundled`, `native_lib`, `pickle_load`, `embedded_blob`, `direct_url_dep`.

Code that runs at enable time and code an app handler runs are what the severities above assume; the same capability in an operator the user clicks is usually informational, and a file the add-on never imports (dev scripts, vendored `site-packages`, docs, tests) drops two levels.

Precision rules that keep popular add-ons clean:

- **Auto-updaters** (download the add-on's own release zip from GitHub and extract it next to `__file__`),
  online asset browsers and AI clients are network use **in operators**: informational.
- `exec(f"from . import {name}")` / `exec(f"{prop}: bpy.props.BoolProperty(...)")` - code *templates*
  whose skeleton is a literal in the add-on - are informational; `exec(<opaque value>)` at enable time is HIGH.
- *Run Script* operators that `exec()` a Text datablock the user picked are informational; the same
  `exec()` inside a `load_post` handler runs the code of **every `.blend` you open, bypassing Auto Run**,
  and is HIGH.
- `pip install` from PyPI is MEDIUM at enable time and LOW in an "Install dependencies" button; from a
  URL or `git+` at enable time it is HIGH.
- Malicious shapes inside a `.blend` are reported as **MEDIUM `blend_payload`** (they only run once
  Auto Run is on, or the user clicks *Allow Execution*). `--strict-blend` scores them at full severity.
- Extensions only: network use with no `network` permission in `blender_manifest.toml` is LOW
  (`undeclared_network`) - a policy gap, not an attack.

## Calibrated, not noisy

Measured on **1,743 real add-ons**: every add-on on extensions.blender.org (1,243) plus the 500 most-starred GitHub repositories tagged `blender-addon` - 40,196 Python files and 428 `.blend` files. They were split once, with a fixed seed, into a calibration set (1,130) and a held-out set (613) that was scanned **once, with the rule set frozen and pushed first** (commit `81a4cf4`).

| | Calibration (1,130) | Held-out (613), rules frozen |
| --- | --- | --- |
| Same signatures, no context rules: HIGH or worse | 224 (19.8%) | 130 (21.2%) |
| `blender-audit`: HIGH or worse | **0** | **1 (0.16%)**, 0 CRITICAL |
| MEDIUM (for review) | 12 (1.1%) | 7 (1.1%) |

The one held-out HIGH was a false positive (`Popen(command, shell=True)` over a literal list of `where` / `whereis` / `which python` probes); it was fixed afterwards with a regression test, so the post-fix 0/613 is **not** a blind number. No add-on in either set was found doing anything malicious.

**Full results: [FINDINGS.md](FINDINGS.md).**

## Usage

```bash
# local folders, single .py add-ons, .zip archives, .tar.gz, .blend
python blender_audit.py path/to/addon path/to/other.zip scene.blend

# extensions.blender.org: reads the archive's central directory with HTTP range requests and
# fetches only .py / .toml / requirements / small .blend members (a 100 MB extension costs a few MB)
python blender_audit.py --extensions <id>

# GitHub (codeload tarball; text sources and .blend <= 20 MB only)
python blender_audit.py --github owner/repo[@ref]

# every add-on, extension and startup script in Blender's user folders (macOS / Linux / Windows)
python blender_audit.py --installed

# a string
python blender_audit.py --text "import os; os.system(...)"

# options: --json | --sarif  --fail-on {critical,high,medium,low,never}  --verbose (show INFO)  --strict-blend  --version
# exit code 2 if anything is HIGH or CRITICAL, 1 if a target could not be fetched (CI-friendly)
```

`.blend` files compressed with zstd (Blender 3.0+ *Compress* option) are decompressed with the `zstd`
CLI if it is installed; otherwise they are reported as not inspected. gzip-compressed (older) files
are handled natively.

### Before you open a downloaded model

```bash
python blender_audit.py downloaded_model.blend || echo "review before enabling Auto Run"
```

And keep **Preferences → Save & Load → Auto Run Python Scripts** off unless you trust the file's
source. `blender-audit` also flags add-ons that switch it on from code.

## Tests

```bash
python tests/run.py
```

43 checks, all passing: 19 inert malicious canaries (stealer in `register()`, stealer in an imported submodule, environment dump, decode-then-exec, download-and-exec - direct, via a variable, via a loop and via a PowerShell cradle - reverse shell on a timer, shell-rc persistence, Blender startup-folder persistence, Auto Run switched on, a `load_post` handler that execs Text datablocks, `pip install git+` at enable time, collector host, `__import__` chain, shadow wheel, typosquat), 12 benign controls taken from what popular add-ons really do (GitHub auto-updater, Run Script operator, handlers that touch properties, ffmpeg, an online asset browser that checks `bpy.app.online_access`, `eval` of a typed expression, preset copying, app-template install, PowerShell clipboard read, `exec(f"from . import {m}")` templates, import-time probes, `where`/`which` loops), MEDIUM / LOW / not-imported controls, five generated `.blend` checks (a stealer, the Morphisec-style loader `Rig_Ui.py` at default and `--strict-blend` severity, and a benign rig UI), `--text` checks and a 2 MB performance check. No test string is in a real provider's credential format.

## Limits

- Static analysis. Code assembled at runtime in ways the parser can't see (e.g. fetched from a server
  at click time and kept in memory) can only be caught by its shape (network response → `exec`).
- Bundled wheels and native libraries are listed, not decompiled.
- `.blend` text extraction follows the block layout Blender writes for Text datablocks; driver
  expressions are matched as strings. A heavily nested or unusual file may hide a script from it.
- Findings are pattern matches for human review, not verdicts.

## Output formats and CI

These flags are shared by every scanner in the eltociear `*-audit` family and behave the same way in each.

| flag | effect |
|---|---|
| `--json` | machine-readable report in the family schema `eltociear-audit/1` (below) |
| `--sarif` | SARIF 2.1.0 on stdout, for GitHub code scanning (`github/codeql-action/upload-sarif`) and other SARIF viewers |
| `--fail-on {critical,high,medium,low,never}` | exit `2` when any target reaches that level. Default `high`, which is the original behaviour. `never` always exits `0` |
| `--version` | prints `blender-audit <version>` |

Exit codes: `0` means no target reached the `--fail-on` level, `2` means at least one did, and `1` is a usage error. If a target can't be fetched or parsed, it's reported with `error` set (in SARIF, as a `toolExecutionNotifications` entry with `executionSuccessful: false`). blender-audit keeps its historic stricter rule here: if a target can't be scanned and nothing reached the threshold, it exits `1`, not `0` (`--fail-on never` still exits `0`).

`--json` schema (`eltociear-audit/1`, one shape for the whole family):

```
{
  "schema": "eltociear-audit/1",
  "tool": {"name": "blender-audit", "version": "x.y.z"},
  "fail_on": "high", "exit_code": 2, "max_severity": "CRITICAL", "errors": 0,
  "results": [{
    "target": "...", "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|SAFE", "risk_score": 0-100,
    "error": null, "counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    "findings": [{"rule_id": "...", "severity": "CRITICAL", "name": "...", "description": "...",
                  "file": "path/in/target", "line": 12, "matched": "...", "context": "..."}],
    "info": [ same shape, severity "INFO": capability context that never raises the risk ],
    "...": "scanner-specific extra fields, unchanged from earlier versions"
  }]
}
```

`results` is always a list, even when there's only one target. Each finding also keeps the scanner's own keys, such as `id`. In SARIF, `CRITICAL` and `HIGH` map to `error`, `MEDIUM` to `warning` and `LOW` to `note`. Rules carry a `security-severity` (9.5 / 8.0 / 5.5 / 3.0), and INFO context isn't emitted. For local targets, `artifactLocation.uri` is relative to the working directory, so run the scanner from the repository root.

```yaml
- run: python3 blender_audit.py . --sarif --fail-on never > blender-audit.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: {sarif_file: blender-audit.sarif}
- run: python3 blender_audit.py . --fail-on high
```

Hostile input handling: archives are read in memory and never extracted to disk. Archive members whose names are traversal (`../`), absolute or drive-letter paths, or contain NUL are skipped. Symlink, hardlink, device and FIFO members are ignored. Each archive has a budget of decompressed bytes and members (bomb protection). Local directory walks only open regular files, so symlinks (including loops and links out of the tree), FIFOs and devices are never followed or read.

## Related

Same engine family: [mcp-audit](https://github.com/eltociear/mcp-audit) ·
[hf-code-audit](https://github.com/eltociear/hf-code-audit) ·
[comfyui-audit](https://github.com/eltociear/comfyui-audit) ·
[npm-audit](https://github.com/eltociear/npm-audit) ·
[vsix-audit](https://github.com/eltociear/vsix-audit)

MIT licensed.
