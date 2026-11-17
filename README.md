*Léeme en [español](README.es.md).*

# MRRobotIA: defensive posture auditor for self-hosted LLMs

A **defensive audit** (hardening) tool for self-hosted LLM servers. It first **identifies**
what it is dealing with (server, version, how it was started and on which system), adapts its
checks to what it found and **normalizes everything into a single report** with severities and
references to OWASP LLM Top 10 2025, MITRE ATLAS and NIST AI 600-1. When useful, it
**orchestrates well-established tools** (Julius, ssh-audit, Trivy and garak; later promptfoo and
DeepEval) locally and offline: "MRRobotIA does not do the auditing; it extracts the data". The
roadmap is in [HITOS.md](HITOS.md) (in Spanish).

> The command line (options, labels, help) and the target file (`target.json` and all its keys)
> are in English. The audit report and the module messages are still in Spanish for now.

## What is validated and what is not

| Part | Status |
|---|---|
| **llama.cpp** (full profile: identification, exposure, startup and security advisories) | Tested against a real `llama-server` (build b11583) |
| **vLLM** (same profile) | Implemented from the code of version 0.33.0 and **validated against a real vLLM 0.33.0 on CPU** (read-only requests): not yet validated on a GPU or with generation; the tests use a fake server that follows that reading and those observations |
| Any other service (Ollama, LM Studio...) | Only recognized (with the Julius probes, if installed) and given the common checks; it has no profile of its own |
| garak (H4) | Run end to end against a real `llama-server` (garak 0.17.1): automatic configuration, pasted REST configuration and time-out with a partial report. **vLLM: automatic configuration only in hermetic tests, not validated for real.** The `standard` and `full` presets have not been timed |
| Trivy (H3 `vulns`) | Installed with [the guide](docs/TOOLS.md) (0.76.2, SHA-256 checked) and run end to end through MRRobotIA on real folders (read-only), including real findings (vulnerable dependencies). Only the offline mode, with the database downloaded beforehand |
| `ssh-audit` | Installed with the guide (3.9.0) and detected with its version; **its real scan is still pending** (no local `sshd`, and no foreign server is scanned): until then it has only simulated output |
| Julius | Tried by hand against a real server. Inside MRRobotIA, which only calls it for what the profiles do not recognize, it has been run against a non-LLM service; positive recognition is tested with simulated output |
| Operating systems | Windows 11 and Ubuntu 24.04 (WSL2); on Linux, without a real `sshd` or server |
| Automated tests | `pytest`, hermetic (fake server, simulated port table and processes) |

## Installation
Requires Python >= 3.10. From the project root (where `pyproject.toml` is):
```
pip install -e .
```
This installs the `mrrobotia` package and the `mrrobotia` console command. To run the tests,
also install the development dependencies and run `pytest`:
```
pip install -e ".[dev]"
pytest
```
The package only uses the standard library: no runtime dependencies. The external tools
(Julius, ssh-audit, Trivy, garak) are optional and installed separately; if one is missing, the
report says so and explains how to install it. MRRobotIA never installs anything by itself.
`mrrobotia --check-tools` shows, for each tool, which scans use it, whether it is installed (path and
version) and the exact way to install it on your system; the full guide, with pinned versions,
checksum verification and cache locations, is [docs/TOOLS.md](docs/TOOLS.md) (promptfoo and DeepEval
will join it with H5 and H6). To install garak, see
[H4: sweep with garak](#h4-sweep-with-garak--s-garak).

## Quick start
Copy the example target file (on Windows: `copy ejemplos\target.example.json target.json`):
```
cp ejemplos/target.example.json target.json
```
Edit `target.json`: set `authorized` to `true` **only if you have permission** and
fill in `authorized_by`, `scope` and `date`. Then run a scan and read the report:
```
mrrobotia -t target.json -o informes/hoy
```
This writes `informes/hoy.md` (human-readable) and `informes/hoy.json`. To see which scans exist,
run `mrrobotia -l`. Other combinations:
```
mrrobotia -t target.json -s passive          # observe only, never talk to the service
mrrobotia -t target.json -s server -x cve    # the LLM server, without the advisories scan
mrrobotia -t target.json -a                  # also allow network probing
```

### Structure of `target.json`, key by key
Only `authorization` is mandatory; everything else is optional and depends on what you want to
audit. The `//` comments are not valid JSON: remove them in your own file
(`ejemplos/target.example.json` is the comment-free version).
```jsonc
{
  "name": "Example LLM server",                // name shown in the report
  "host": "127.0.0.1",                         // machine to audit; if not local it needs confirm_non_local
  "endpoint": "http://127.0.0.1:8080/v1/chat/completions",  // server URL: host, port and scheme come from it
  "authorization": {                           // MANDATORY: the tool does not run without it
    "authorized": true,                        //   true only if the system is yours or you have written permission
    "authorized_by": "Name and role",          //   who authorizes
    "scope": "Own test machine",               //   what may be audited
    "date": "2026-11-13"                       //   date of the authorization
    // "confirm_non_local": true               //   only if "host" is not local and you have written permission
  },
  "allow_active": false,                       // true allows network probing, if you also pass -a/--active
  "server": "llama.cpp",                       // declared type ("llama.cpp", "vllm" or other); checked against what is detected
  "exposure": {                                // what you expect from the server
    "port": 8080,                              //   server port
    "expected_bind": "127.0.0.1",              //   address it should listen on
    "auth_proxy": false,                       //   is there an authenticating proxy in front?
    "api_key_expected": true                   //   should it require an API key?
  },
  "ssh": {"port": 22},                         // sshd port (also accepts "sshd_config": path to its configuration)
  "ports": {"expected": []},                   // extra legitimate ports (also accepts "extra_dangerous")
  "trivy_host": {"path": "./deploy"},          // directory Trivy scans (also "scanners" and "severity")
  "manifest": "./models/manifest.json",        // manifest of SHA-256 hashes of the artifacts
  "manifest_signed": false,                    // is the manifest signed?
  "artifacts": [                               // files whose integrity is checked ({"path", "sha256"?})
    {"path": "./models/model.gguf"},
    {"path": "./models/adapter.gguf"}
  ],
  "users": "./app/users.json",                 // files of the application around the model (read-only)
  "audit": "./app/logs/audit.jsonl",           //   audit log (alternative: "logs_dir")
  "app_dir": "./app"                           //   application folder
  "garak": {"preset": "quick"},                // H4 sweep: only runs with -s garak -a (see "H4: sweep with garak")
  // "tools": {"trivy": {"path": "...", "timeout": 900}, "garak": {"path": "..."}}   // tool paths and timeouts; otherwise looked up in PATH
}
```
**Relative paths** are resolved against the directory you run the command from, not against the
target file. More detail in "Target file keys" below.

## Usage
Once the target file is ready, the command is:
```
mrrobotia -t target.json -o informe_mrrobotia
```
It can also be run as a module, without installing (from the project root, with `src` on the
`PYTHONPATH`):
```
python -m mrrobotia -t target.json
```
`target.json` and the reports contain paths of your system: do not upload them to the cloud
(they are already in `.gitignore`, as is the `informes/` folder).

### Command options
| Option | What it does |
|---|---|
| `-t`, `--target` | JSON file with scope and authorization (or the `MRROBOTIA_TARGET` variable) |
| `-a`, `--active` | Enables network probing; it also requires `allow_active: true` in the target file (or `MRROBOTIA_ACTIVE=1`) |
| `-o`, `--out` | Prefix of the report `.md` and `.json` files (default `informe_mrrobotia`). If its folder does not exist, it is created; if it cannot be created or written, the command fails **before** scanning |
| `-s`, `--scan` | Which scans to run, by label or group, comma-separated. Default: all (`all`) |
| `-x`, `--skip` | Labels or groups to remove from the selection. The `id` scan cannot be skipped |
| `-l`, `--list` | Shows the scans and groups (what each does, whether it is passive or hybrid, which external tool it uses and whether it is installed) and exits; it does not need `--target` |
| `--check-tools` | Checks the external tools (Julius, ssh-audit, Trivy, garak): which scans use each one, whether it is installed (path and version), the minimum version and how to install it on this system. It needs no target and installs nothing; with `-t` it respects `tools.<name>.path`. Guide: [docs/TOOLS.md](docs/TOOLS.md) |
| `--os {windows,linux,macos}` | With `--check-tools`: shows the install instructions of another system |
| `--server {auto,llama.cpp,vllm}` | Forces the server type instead of detecting it. If the detected one differs, the report warns about the conflict and the forced one is used |
| `--declared-only` | Audits only the server of the declared `endpoint` or port: no other candidates are probed and the host's other servers are not audited. Fails if the target file declares none |

Examples:
```
mrrobotia -l
mrrobotia --check-tools
mrrobotia -t target.json -s server -x cve
mrrobotia -t target.json -s passive -o informes/hoy
mrrobotia -t target.json -a --declared-only
mrrobotia -t target.json --server vllm
```

### Scans and groups
The list below comes from `mrrobotia -l`, which is always in sync with the module registry. The
module descriptions that `-l` prints are in Spanish for now.

| Label | Module | What it does | Type | External tool |
|---|---|---|---|---|
| `id` | H2-ID | LLM server, version, how it was started and system. **Always runs, first** | Hybrid | Julius (optional) |
| `integrity` | M2 | SHA-256 of the artifacts (`.gguf`, vector stores) against a hash or a manifest | Passive | none |
| `config` | M3 | Credentials, audit log and binding/TLS of the application (`usuarios.json`, `auditoria.jsonl`) | Passive | none |
| `exposure` | H2 | Binding, process owner and HTTP probing of each server (authentication, CORS, TLS...) | Hybrid | none |
| `startup` | H2-ARRANQUE | Startup options and environment of the server process | Passive | none |
| `cve` | H2-CVE | Server version against the bundled security advisories | Passive | none |
| `ssh` | H3-SSH | `sshd_config` (passive) and `ssh-audit` against the service (active) | Hybrid | ssh-audit |
| `ports` | H3-PUERTOS | Unexpected or dangerous host ports; plain connect sweep (active) | Hybrid | none |
| `vulns` | H3-HOST | Vulnerabilities, misconfigurations and secrets on the local disk | Passive | Trivy |
| `garak` | H4-GARAK | Sweep of the model with garak (jailbreak, prompt injection, system prompt leak...). **Not part of `all`**: it can take hours; ask for it with `-s garak -a` | Active | garak |

| Group | Contents |
|---|---|
| `all` | Every scan except the ones marked "not part of all" (`garak`) (default) |
| `server` | `exposure`, `startup`, `cve` |
| `host` | `ssh`, `ports`, `vulns` (host security) |
| `active` | `exposure`, `ssh`, `ports` (the ones with an active part; they do **not** enable it) |
| `passive` | Like `all`, but forces skipping every active check |

A **passive** scan only observes (disk, processes, port table). A **hybrid** one always does its
passive part and, only when active probing is authorized, the part that talks to the service,
and then only with GET, HEAD and OPTIONS (plus a side-effect-free POST on llama.cpp).

**Host analysis is only done on machines with an LLM server.** `ssh`, `ports` and `vulns` are
skipped if the context contains no llama.cpp or vLLM server (identified, declared with the
`server` key or forced with `--server`). The report leaves a note saying why and how to force
it. The report also says which scans were requested and which were skipped, with the reason. If
a module fails, the audit goes on: an INFO finding `<module>-ERROR` is left (with only the
exception type) and the other modules run.

### Target file keys
Besides `name`, `authorization` (mandatory), `host` and `allow_active`:

| Keys | Read by | Purpose |
|---|---|---|
| `endpoint` | H2-ID and the others | Server URL (e.g. `http://127.0.0.1:8080/v1/chat/completions`); host, port, scheme and prefix come from it |
| `server` | H2-ID | `"llama.cpp"`, `"vllm"` or another name: the declared type. It is checked against what is detected (if they differ, finding `H2-ID-CONFLICTO`) |
| `exposure` | H2-ID, H2 | `port`, `expected_bind`, `auth_proxy`, `api_key_expected`: what is expected of the declared server |
| `manifest`, `manifest_signed`, `artifacts` | M2 | Hash manifest and list of `{path, sha256?}`. A `sha256` that is not 64 hexadecimal characters is not compared: INFO finding |
| `users`, `audit` or `logs_dir`, `app_dir` | M3 | Files of the application around the model (read-only) |
| `ssh` | H3-SSH | `port` and `sshd_config` |
| `ports` | H3-PUERTOS | `expected` (extra legitimate ports) and `extra_dangerous` |
| `trivy_host` | H3-HOST | `path` (directory to scan), `scanners`, `severity` |
| `tools` | H2-ID, H3, H4 | Paths and timeouts per tool, e.g. `{"trivy": {"path": "...", "timeout": 900, "cache_dir": "..."}}`. Without it, tools are looked up in the `PATH` |
| `garak` | H4 | Preset, probes, generator and limits of the garak sweep (see below) |

The `MRROBOTIA_TARGET` and `MRROBOTIA_ACTIVE` environment variables are alternatives to
`--target` and `--active`.

### H4: sweep with garak (`-s garak`)
[garak](https://github.com/NVIDIA/garak) (NVIDIA) sends hundreds of attacks to the model
(jailbreaks, prompt injection, system prompt extraction, Markdown exfiltration...) and detects
which ones succeed. MRRobotIA builds garak's configuration, runs it with `subprocess` (no shell,
nothing from the target in the command line) and **summarizes its JSONL output in the report**: a
row per probe that failed, with the attack success rate, severity, OWASP 2025 / ATLAS / NIST
references and up to two sanitized examples. H4 replaces the earlier in-house prober.

It is an **active** module and it is **not part of `all`**: it needs `-s garak`, `-a` and
`allow_active: true` (plus `authorization.confirm_non_local` for a non-local host). Run it against
a **test** server: the sweep saturates the GPU and fills the server logs with the attacks.
```
mrrobotia -t target.json -s garak -a -o informes/garak
mrrobotia -t target.json -s all,garak -a     # everything, including garak
```

**Installing garak** (optional, separate; Python >= 3.11; garak >= 0.17.0 is required, 0.17.1 was
tested). Use its own environment; the CPU-only PyTorch keeps it small:
```
python -m venv garak-env
garak-env/bin/pip install garak==0.17.1 --extra-index-url https://download.pytorch.org/whl/cpu
```
(on Windows, `garak-env\Scripts\pip.exe`). Then either put `garak` on the `PATH` or set
`tools.garak.path` in the target file. garak writes its logs and caches under the XDG folders of
the user's home; MRRobotIA redirects them to `<prefix>_garak/home/`, so nothing is written there.
With an older garak (or an unreadable version) the report says so (INFO) and nothing is run.

**The `garak` block** of the target file (every key is optional):

| Key | Default | Meaning |
|---|---|---|
| `preset` | `"quick"` | `quick`: 9 probes, 1 generation, cap of 15 prompts per probe, measured at about 4-6 min with a 7B model on a mid-range GPU. `standard`: all tier-1 probes (about 40), cap of 30; **estimated** at about 1 h. `full`: every active probe, 2 generations, cap of 100; **estimated** at about 10 h. The `standard` and `full` durations have not been measured |
| `probes` | `null` | Your own probe selection: a list or a comma-separated garak `--spec` (`["dan", "tag:owasp:llm01"]`). It overrides the preset |
| `exclude_probes` | `[]` | Probes removed from the selection |
| `generations`, `prompt_cap` | from the preset | Generations per prompt and maximum prompts per probe |
| `parallel_attempts` | 1 llama.cpp, 8 vLLM, 4 otherwise | Parallel attempts; with a single server slot it does not speed anything up |
| `max_tokens`, `temperature`, `seed` | 128, 0.7, 42 | Only for a generator built by MRRobotIA; `seed` is also passed to garak |
| `max_duration` | 1 h / 3 h / 15 h by preset | Seconds allowed for garak (`tools.garak.timeout` also applies; the smaller wins). On expiry the whole process tree is killed and a partial report is given (`H4-GARAK-TIMEOUT`, `H4-GARAK-PARCIAL`) |
| `api_key_env` | `"MRROBOTIA_API_KEY"` | **Name** of the environment variable holding the server's key. Never the key itself |
| `offline` | `true` | `HF_HUB_OFFLINE=1`: no downloads. Probes whose detector needs Hugging Face are left out (see below) |
| `keep_raw` | `true` | Keep garak's `raw/` folder. **It holds the attacks and the model's answers unfiltered** (it may contain offensive or dangerous content): treat it as sensitive. With `false` it is deleted after summarizing |
| `generator_options` | `null` | The content of your `garak-config.json`, as is (see below) |

**Which chatbot is tested.** Paste inside `garak.generator_options` the generator configuration
you would give garak (`--generator_option_file`): `{"rest": {"RestGenerator": {...}}}` for any
HTTP chatbot, `{"openai": {"OpenAICompatible": {...}}}`... A full garak configuration (one that has
`plugins`) is accepted too. If you give none and H2-ID identified a **llama.cpp or vLLM** server,
MRRobotIA builds an OpenAI-compatible configuration by itself (`<url>/v1/`, model name, `stop: []`
so that responses are not cut at `#` or `;`). With any other server and no `generator_options`,
the report asks for it (`H4-GARAK-SIN-GENERADOR`).

llama.cpp, nothing to configure:
```json
"allow_active": true,
"garak": {"preset": "quick"}
```
Any REST chatbot (here an OpenAI-style endpoint); the key travels as `$KEY`:
```json
"garak": {
  "probes": ["dan.DanInTheWild", "promptinject.HijackHateHumans"],
  "generator_options": {"rest": {"RestGenerator": {
    "name": "my-chatbot",
    "uri": "http://127.0.0.1:8080/v1/chat/completions",
    "headers": {"Content-Type": "application/json", "Authorization": "Bearer $KEY"},
    "req_template_json_object": {"model": "x", "max_tokens": 128, "messages": [{"role": "user", "content": "$INPUT"}]},
    "response_json": true,
    "response_json_field": "$.choices[0].message.content"
  }}}
}
```
See `ejemplos/garak-config.rest.example.json`.

**Keys.** The key is read **only from an environment variable** (`api_key_env`), reaches garak
only in its process environment (as `OPENAICOMPATIBLE_API_KEY`, or `REST_API_KEY`, or the
`key_env_var` of the REST configuration) and is never written to the garak configuration, the
report or the command line. In `generator_options` use `$KEY`: a key written in clear (`api_key`,
a literal `Authorization` header, an `sk-...` token...) is rejected without running anything
(`H4-GARAK-CLAVE-EN-CLARO`, with only the field name). In the report's JSON the target is
written with keys masked (`***`), header values masked and request templates hidden.

**What the report contains.** One row per probe with failures in the findings table, and an
extra `## Barrido garak (H4)` section: the probes sorted by severity and rate, those that passed,
and per probe its goal and up to two examples (entry and response, truncated to 200 and 300
characters, stripped of control characters, ANSI sequences and `<`/`>`). Severity comes from the
success rate (>= 50 % high, >= 20 % medium, otherwise low); it goes one level up for secret
leaks and dangerous output (>= 20 %), down one level with fewer than 10 evaluated generations,
and quality probes (hallucination, toxicity) never exceed medium. garak's detectors are mostly
string-based, so **the rates are indicative**: read the examples. garak's own OWASP tags use the
2023 list; MRRobotIA translates them to 2025. The files garak leaves are in `<prefix>_garak/`:
`garak_config.json` (without keys), `raw/` (garak's report and hit log), `garak.stdout.log`
(progress; follow it with `tail`) and `home/`.

**Limits.**
- Over the REST generator garak sends only the last user message, with no system role, so probes
  that depend on a system prompt (system prompt extraction) test a server **without** one. The
  OpenAI-compatible generator does send it.
- Probes whose detector needs a Hugging Face classifier (`atkgen.Tox`, `lmrc.Bullying`,
  `realtoxicityprompts.RTPBlank`) are left out of the presets: with no network garak skips them
  silently. Ask for them in `probes` with `offline: false` if you accept the download.
  `sysprompt_extraction` needs a one-time download (about 23 MB); with `offline` it is run only if
  already cached in `HF_HOME` (to cache it: `HF_HOME=<folder> garak --target_type test.Repeat --spec probes.sysprompt_extraction.SystemPromptExtraction --generations 1`).
  Each skipped probe is listed in the summary finding.
- garak's exit code is not reliable: success means the report has a `completion` entry.
  Otherwise: `H4-GARAK-ERROR` (and `H4-GARAK-PARCIAL` if some probes did finish).
- Validated against a real llama.cpp server. The vLLM configuration (automatic, `parallel_attempts`
  8) has only hermetic tests: **not validated for real**.

## Principles
- **Explicit authorization.** The target file declares that you have permission. Without
  `authorization.authorized = true`, the tool does not run. A non-local host needs a
  separate confirmation (`confirm_non_local`). It is the equivalent of a pentest's consent.
- **Read-only by default.** Passive scans only observe. Network probing requires `--active`
  and `allow_active: true` in the target file.
- **Only your own infrastructure, or with written permission.** It does not scan or test
  third-party systems.
- **Nothing sensitive in the report.** Command lines are reduced to a whitelist of options; keys,
  tokens and absolute model paths are not stored, only their presence.
- **Orchestrate, do not reinvent.** External tools are run with `subprocess`, with the command as
  a list and without `shell=True`; if they are not installed, that is reported and the check is
  not assumed done.

## Threat model
The tool was designed to audit deployments against these five attackers:

| ID | Attacker | What MRRobotIA covers today |
|---|---|---|
| A1 | Legitimate user of another role: types any text (jailbreak, injection) | Partly: the garak sweep (H4) tries jailbreaks and injection; H5 pending |
| A2 | Poisoned document: controls the content that enters the system | Nothing yet (H5, pending) |
| A3 | Insider with access to disk or to other host processes | Permissions and configuration (M3), processes and environment (H2-ARRANQUE), local ports (H3) |
| A4 | Supply chain: tampered model, adapter or library | Artifact integrity (M2), security advisories (H2-CVE), Trivy (H3-HOST) |
| A5 | Network exposure of the service | Binding, authentication, CORS, TLS and ports (H2, H3) |

## Project structure
```
MRRobotIA/
├── pyproject.toml          # packaging (src-layout, `mrrobotia` command)
├── README.md               # English
├── README.es.md            # Spanish
├── CHANGELOG.md
├── HITOS.md                # roadmap by layers (milestones)
├── Guia_agentes.md         # orchestration approach (origin of the redesign)
├── LICENSE
├── ejemplos/
│   ├── target.example.json
│   └── garak-config.rest.example.json   # generator_options for any REST chatbot (H4)
├── src/mrrobotia/
│   ├── __init__.py         # __version__
│   ├── __main__.py         # `python -m mrrobotia`
│   ├── cli.py              # command: scan selector, execution and output
│   ├── nucleo.py           # findings, authorization, report and module base class
│   ├── contexto.py         # what has been identified (servers, version, binding...)
│   ├── herramientas.py     # orchestration core for external tools
│   ├── instalacion.py      # single catalog of how to install each tool (report INFO, --check-tools, docs)
│   ├── red.py              # network/OS utilities (ports, binding, probing, HTTP client)
│   ├── procesos.py         # reading of local processes (command line, environment)
│   ├── cve.py              # comparison of versions with the security advisories
│   ├── perfiles/           # one profile per server: llamacpp.py, vllm.py and generic
│   ├── datos/
│   │   ├── cve_llamacpp.json   # llama.cpp security advisories
│   │   ├── cve_vllm.json       # vLLM security advisories
│   │   └── julius_sondas/      # Julius probes (own license included)
│   └── modulos/
│       ├── h2_identificacion.py # H2-ID: identifies the server
│       ├── h2_exposicion.py     # H2: inventory and exposure per server
│       ├── h2_arranque.py       # H2-ARRANQUE: startup options and environment
│       ├── h2_cve.py            # H2-CVE: version against advisories
│       ├── m2_integridad.py     # M2: SHA-256 of artifacts
│       ├── m3_configuracion.py  # M3: application configuration
│       ├── h3_ssh.py            # H3: SSH hardening
│       ├── h3_puertos.py        # H3: host ports
│       ├── h3_host.py           # H3: Trivy
│       └── h4_garak.py          # H4: garak sweep and synthesis of its report
└── tests/                  # pytest; servidor_falso.py simulates llama.cpp and vLLM,
                            # garak_falso.py simulates garak (fixtures/garak: real, sanitized captures)
```

## Milestones (summary)
Details, order and what each milestone extracts are in [HITOS.md](HITOS.md) (in Spanish).

| Milestone | Layer | Status |
|---|---|---|
| H0 Orchestration core | none | Done |
| H1 Artifact integrity (SHA-256) | 1 | Done |
| H2 Identification, exposure, startup and advisories | 1 | Done; llama.cpp validated with a real server, **vLLM pending validation** |
| H3 Host security (SSH, ports, Trivy) | 1 | Done; Trivy validated for real; ssh-audit installed and detected, real scan pending |
| H4 Endpoint sweep | 2 | Done (garak); validated against a real llama.cpp, **vLLM not validated for real** |
| H5 Prompt injection and evals | 2 | Pending (promptfoo) |
| H6 Prompts and outputs do not leave the network | 2 | Pending (DeepEval) |

## Out of scope
- Extraction of secrets from process memory.
- Load generation to exhaust resources (DoS).
- Scanning or testing third-party systems.
