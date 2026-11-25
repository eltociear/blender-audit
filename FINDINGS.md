# What we found scanning 1,743 Blender add-ons

This is the research behind `blender-audit`: a real scan of the Blender add-on ecosystem, run
with this exact engine, calibrated so that a "clean" result means clean before any number is
reported. Like the rest of the family ([mcp-audit](https://github.com/eltociear/mcp-audit/blob/main/FINDINGS.md),
[hf-code-audit](https://github.com/eltociear/hf-code-audit), [comfyui-audit](https://github.com/eltociear/comfyui-audit)),
nothing here names an add-on as malicious; observed patterns are described in aggregate.

## Method

1. **extensions.blender.org: every add-on.** The platform's public listing
   (`/api/v1/extensions/`, snapshot 2026-11-26) has 1,403 add-on archives for **1,243 add-on
   ids** (plus 303 themes and 8 asset libraries, not scanned). One archive per id: the
   platform-independent build, else the smallest. Archives over 4 MB were read with HTTP range
   requests: the zip central directory first, then only `.py`, `.toml`, requirements files and
   `.blend` files of 20 MB or less.
2. **GitHub: the 500 most-starred repositories tagged `blender-addon`.** Repos up to 20 MB were
   fetched as one tarball. Larger ones were read through the git tree, text sources only and no
   `.blend` files.
3. **Kept:** 40,196 Python files and 428 `.blend` files, 1.1 GB, never imported, enabled or
   opened in Blender. Every item was scanned in its own process with a hard timeout. None
   timed out.
4. **Split once, with a fixed seed (`20261126`)**, into a calibration set of 1,130 (800
   extensions, 330 GitHub repos) and a held-out set of 613 (443, 170). Rules were tuned only on
   the calibration set. They were then frozen and pushed (commit `81a4cf4`) **before** the
   held-out set was scanned for the first time.

## Headline

| Result | Calibration (1,130) | Held-out (613), rules frozen |
| --- | --- | --- |
| **Clean or informational only** | 1,084 (95.9%) | 584 (95.3%) |
| LOW (policy gaps, operator-time `pip install`) | 34 | 21 |
| MEDIUM (for review) | 12 | 7 |
| **HIGH / CRITICAL** | **0** | **1 (0.16%)**, 0 CRITICAL |
| Same signatures, no context rules: HIGH or worse | 224 (19.8%) | 130 (21.2%) |

**No add-on in either set was found doing anything malicious.** The one held-out HIGH was a
false positive: a debugger add-on looks for Python with a loop over a literal list
(`["where", "python"]`, `["whereis", "python"]`, `["which", "python"]`) passed to
`Popen(..., shell=True)` at register time. It was fixed afterwards, with a regression fixture and
a matching malicious canary (a loop over a `curl … | sh` string still scores CRITICAL).
Re-scanned with the final rules, the held-out set is 0/613 HIGH+. That number is **not** blind,
and is not the one quoted above.

All 19 MEDIUMs were reviewed by hand. None is an attack:

| MEDIUM | Items | What it is |
| --- | --- | --- |
| `pip install` when the add-on is enabled | 7 | Dependency bootstrap in `register()` (PyPI names, `ensurepip`, `--user`) |
| `pip install` from an index URL or wheel file in an operator | 4 | "Install dependencies" buttons pulling `torch` from `download.pytorch.org` or a downloaded wheel |
| CRITICAL shapes in files the add-on never imports | 4 | Vendored `pip` / `distlib` inside a bundled `site-packages` (the `.pypirc` upload path, `sitecustomize` writes); a release script reading `GITHUB_TOKEN`; a model-download installer reading `HF_TOKEN` |
| Opaque `exec` / `eval` at enable time | 3 | Loading the add-on's own preset, menu or operator files; `importlib.reload(eval(module))` |
| Custom package index | 1 | An engine's own nightly wheel index |

## The noise: what looks dangerous in a Blender add-on but isn't

Scored without context, the same signatures flag **354 of 1,743 add-ons (20.3%)** HIGH or
worse: 10.1% of extensions and 45.8% of GitHub repos. None of them turned out to be an attack:
with context, every one lands in SAFE, LOW or one of the hand-reviewed MEDIUMs above. What
drives it (an item can appear in several rows):

| Signal | Items | Why it's noise in Blender |
| --- | --- | --- |
| `exec` / `eval` / `subprocess` in operators, probes and code templates | 325 (18.6%) | 261 have them in code that only runs when the user clicks a button: Run Script operators, `eval` of a typed expression, launching ffmpeg, an external editor, a file browser. 116 have them in files the add-on never imports. At enable time (21) and in handlers (19) they are code templates such as `exec(f"from . import {name}")` and `exec(f"{prop}: bpy.props.BoolProperty(...)")`, where the skeleton is a literal in the add-on, or tool probes such as `which python` |
| `pip install` from code | 67 (3.8%) | AI and science add-ons install `torch`, `numpy`, `scipy` into Blender's Python. 37 do it behind a button, 27 in scripts the add-on never imports, 7 at enable time |
| `shell=True` / `os.system` with a built command | 41 (2.4%) | Tool launches behind a button (25), and build and release scripts (`7z a …`, `zip …`) next to the add-on that it never imports (16) |
| A **handler** that runs code | 19 (1.1%) | `load_post` / `depsgraph_update` handlers that call tools or eval property paths. Only `exec()` of a `.blend`'s Text datablocks inside a handler is the attack shape (it bypasses Auto Run); none of the 1,743 do it |
| `use_scripts_auto_execute = True` | 2 | Headless test runners in `tests/`, never shipped as add-on code |
| `.pypirc` / `sitecustomize` / `getattr(builtins, "exec")` / token reads | 5 | Vendored `pip`, `distlib`, `requests` and `botocore` copies and release scripts, never imported by the add-on |

The pattern is the same one the MCP, npm and Hugging Face scans showed: **each of these is a
capability, not an attack.** Add-ons *must* run tools, install dependencies and evaluate
expressions. The context that separates the two is **when** the code runs (enable time, a
handler, or a button) and **whether the add-on imports the file at all**. `blender-audit`
follows imports from each add-on's `__init__.py` (falling back to every importable module when
the add-on loads modules dynamically) and tags every finding with that timing.

Three more rules came out of calibration, each with a regression fixture:

- **App templates are not startup persistence.** Copying `startup.blend` into
  `scripts/startup/bl_app_templates_user` is the documented way to install an app template.
  Writing a `.py` into `scripts/startup` itself would run outside the add-on on every launch,
  and stays HIGH.
- **Cloud metadata is not credential theft by itself.** A cloud render manager reads its own
  instance's `169.254.169.254` metadata. The URL only counts as a credential source next to a
  collector host or split-literal hiding.
- **`powershell -EncodedCommand` is not a cradle by itself.** One add-on base64-encodes a local
  clipboard-reading script, which is ordinary Windows quoting. Encoded commands count only in a
  file that also uses the network. `IEX (…).DownloadString(…)` stays CRITICAL.

## What the ecosystem looks like

| | extensions.blender.org (1,243) | GitHub top 500 | All (1,743) |
| --- | --- | --- | --- |
| Uses the network in imported code | 2.7% | 20.6% | 7.8% |
| …at enable time, not behind a button | 0 | 0.8% | 0.2% |
| Of those using the network, checks `bpy.app.online_access` | 20 of 33 | 14 of 103 | 34 of 136 |
| Runs external processes | 8.1% | 28.8% | 14.1% |
| Installs packages from code | 0.3% | 8.0% | 2.5% |
| Registers app handlers or timers | 36.0% | 40.2% | 37.2% |
| Bundles wheels (`blender_manifest.toml`) | 8.3% (933 wheels) | 5.0% (638) | 7.3% |
| Ships an auto-updater | 0.2% | 5.6% | 1.8% |

**The extensions platform is measurably cleaner than GitHub.** Its rules (bundled wheels
instead of `pip` at runtime, a declared `network` permission, `bpy.app.online_access`) show up
in the code. Only 4 of 1,243 extensions install packages from code, against 40 of 500 GitHub
repos, and none touches the network at enable time. The gap is in **declarations**: of the 33
extensions whose imported code uses the network, 27 declare the `network` permission and 6 don't,
mostly because of a bundled updater (`undeclared_network`, LOW). 13 of the 33 never check
`bpy.app.online_access`. Another 22 declare `network` without network code we could see, which is
usually a manifest written ahead of the feature or network use in a bundled wheel.

**Handlers are everywhere.** 37% of add-ons hook `bpy.app.handlers` or timers, so their code
runs on every file load, save or frame change without a click. That is legitimate, and it is
also why a handler that `exec()`s a `.blend`'s Text datablocks gets its own HIGH rule: it would
turn every file you open into code that runs, with Auto Run off.

## `.blend` files

128 items ship 428 `.blend` files of 20 MB or less. 12 of them carry 184 embedded Python texts:
rig UIs, gizmo setups, test scenes. **None contains a malicious shape.** 44 `.blend` files were
zstd-compressed and could not be inspected on the scanning machine (no `zstd` CLI). The tool
reports those as `blend_compressed` instead of passing them silently.

This is the vector that has actually been used against Blender users. In November 2025
[Morphisec reported](https://www.morphisec.com/blog/morphisec-thwarts-russian-linked-stealc-v2-campaign-targeting-blender-users-via-malicious-blend-files/)
a campaign that planted `.blend` files on 3D model marketplaces such as CGTrader. Each carried a
weaponized `Rig_Ui.py` in `bpy.data.texts`. With *Auto Run Python Scripts* enabled, it fetched
a loader from a Cloudflare Workers URL and ended in the StealC V2 infostealer. `tests/run.py`
generates an inert `.blend` with that shape (a rig-UI panel whose `register()` fetches and
`exec`s a URL). `blender-audit` reports it as MEDIUM `blend_payload` by default, because it only
runs once Auto Run is on, and as CRITICAL `download_execute` with `--strict-blend`.

## Takeaways

1. **Keep Auto Run Python Scripts off** and scan downloaded `.blend` files before enabling it.
   A model from a marketplace is code until proven otherwise.
2. **Judge an add-on by what runs at enable time and in handlers.** Operators run only when you
   click. `register()`, module bodies and handlers run every session.
3. **Prefer extensions.blender.org builds.** The platform's rules leave visible traces in the
   code: bundled wheels, declared permissions, `online_access` checks.
4. **Re-scan on update.** An add-on with an auto-updater rewrites its own code from the
   network, and a release is one commit from changing.

---

Reproduce: `python blender_audit.py --extensions <id>`, `--github owner/repo`, or a local path.
The per-item results come from the same engine at commit `81a4cf4` (held-out) and the current
`main` (calibration re-check and the statistics above).

*Findings are pattern matches warranting human review, not verdicts. Suspected malicious add-ons
should be reported to the Blender extensions moderators or the repository host, not published as
unverified accusations.*
