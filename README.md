*Léeme en [español](README.es.md).*

# MRRobotIA: defensive posture auditor for self-hosted LLMs

A **defensive audit** (hardening) tool for self-hosted LLM servers. It first **identifies**
what it is dealing with (server, version, how it was started and on which system), adapts its
checks to what it found and **normalizes everything into a single report** with severities and
references to OWASP LLM Top 10 2025, MITRE ATLAS and NIST AI 600-1. When useful, it
**orchestrates well-established tools** (Julius, ssh-audit, Trivy; later garak, promptfoo and
DeepEval) locally and offline: "MRRobotIA does not do the auditing; it extracts the data". The
roadmap is in [HITOS.md](HITOS.md) (in Spanish).

> The command line (options, labels, help) is in English. The audit report, the module messages
> and the keys of the target file (`autorizacion`, `endpoint`, `exposicion`...) are still in
> Spanish for now.

## What is validated and what is not

| Part | Status |
|---|---|
| **llama.cpp** (full profile: identification, exposure, startup and security advisories) | Tested against a real `llama-server` (build b11583) |
| **vLLM** (same profile) | Implemented from the code of version 0.33.0 and **not validated against a real server**: the tests use a fake server that follows that reading |
| Any other service (Ollama, LM Studio...) | Only recognized (with the Julius probes, if installed) and given the common checks; it has no profile of its own |
| Trivy and `ssh-audit` | Only with simulated output: the real tools have not been run |
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
(Julius, ssh-audit, Trivy) are optional and installed separately; if one is missing, the report
says so and explains how to install it.

## Quick start
Copy the example target file (on Windows: `copy ejemplos\objetivo.ejemplo.json objetivo.json`):
```
cp ejemplos/objetivo.ejemplo.json objetivo.json
```
Edit `objetivo.json`: set `tengo_autorizacion` to `true` **only if you have permission** and
fill in `autorizado_por`, `ambito` and `fecha`. Then run a scan and read the report:
```
mrrobotia -t objetivo.json -o informes/hoy
```
This writes `informes/hoy.md` (human-readable) and `informes/hoy.json`. To see which scans exist,
run `mrrobotia -l`. Other combinations:
```
mrrobotia -t objetivo.json -s passive          # observe only, never talk to the service
mrrobotia -t objetivo.json -s server -x cve    # the LLM server, without the advisories scan
mrrobotia -t objetivo.json -a                  # also allow network probing
```

### Structure of `objetivo.json`, key by key
Only `autorizacion` is mandatory; everything else is optional and depends on what you want to
audit. The `//` comments are not valid JSON: remove them in your own file
(`ejemplos/objetivo.ejemplo.json` is the comment-free version).
```jsonc
{
  "nombre": "Servidor LLM de ejemplo",        // name shown in the report
  "host": "127.0.0.1",                         // machine to audit; if not local it needs confirmo_no_local
  "endpoint": "http://127.0.0.1:8080/v1/chat/completions",  // server URL: host, port and scheme come from it
  "autorizacion": {                            // MANDATORY: the tool does not run without it
    "tengo_autorizacion": true,                //   true only if the system is yours or you have written permission
    "autorizado_por": "Name and role",         //   who authorizes
    "ambito": "Own test machine",              //   what may be audited
    "fecha": "2026-11-13"                      //   date of the authorization
    // "confirmo_no_local": true               //   only if "host" is not local and you have written permission
  },
  "permitir_activos": false,                   // true allows network probing, if you also pass -a/--active
  "servidor": "llama.cpp",                     // declared type ("llama.cpp", "vllm" or other); checked against what is detected
  "exposicion": {                              // what you expect from the server
    "puerto": 8080,                            //   server port
    "bind_esperado": "127.0.0.1",              //   address it should listen on
    "proxy_autenticador": false,               //   is there an authenticating proxy in front?
    "api_key_esperada": true                   //   should it require an API key?
  },
  "ssh": {"puerto": 22},                       // sshd port (also accepts "sshd_config": path to its configuration)
  "puertos": {"esperados": []},                // extra legitimate ports (also accepts "extra_peligrosos")
  "host_trivy": {"ruta": "./despliegue"},      // directory Trivy scans (also "escaneres" and "severidad")
  "manifiesto": "./modelos/manifiesto.json",   // manifest of SHA-256 hashes of the artifacts
  "manifiesto_firmado": false,                 // is the manifest signed?
  "artefactos": [                              // files whose integrity is checked ({"ruta", "sha256"?})
    {"ruta": "./modelos/modelo.gguf"},
    {"ruta": "./modelos/adaptador.gguf"}
  ],
  "usuarios": "./app/usuarios.json",           // files of the application around the model (read-only)
  "auditoria": "./app/logs/auditoria.jsonl",   //   audit log (alternative: "dir_logs")
  "app_dir": "./app"                           //   application folder
  // "herramientas": {"trivy": {"ruta": "...", "timeout": 900}}   // tool paths and timeouts; otherwise looked up in PATH
}
```
**Relative paths** are resolved against the directory you run the command from, not against the
target file. More detail in "Target file keys" below.

## Usage
Once the target file is ready, the command is:
```
mrrobotia -t objetivo.json -o informe_mrrobotia
```
It can also be run as a module, without installing (from the project root, with `src` on the
`PYTHONPATH`):
```
python -m mrrobotia -t objetivo.json
```
`objetivo.json` and the reports contain paths of your system: do not upload them to the cloud
(they are already in `.gitignore`, as is the `informes/` folder).

### Command options
| Option | What it does |
|---|---|
| `-t`, `--target` | JSON file with scope and authorization (or the `MRROBOTIA_TARGET` variable) |
| `-a`, `--active` | Enables network probing; it also requires `permitir_activos: true` in the target file (or `MRROBOTIA_ACTIVE=1`) |
| `-o`, `--out` | Prefix of the report `.md` and `.json` files (default `informe_mrrobotia`). If its folder does not exist, it is created; if it cannot be created or written, the command fails **before** scanning |
| `-s`, `--scan` | Which scans to run, by label or group, comma-separated. Default: all (`all`) |
| `-x`, `--skip` | Labels or groups to remove from the selection. The `id` scan cannot be skipped |
| `-l`, `--list` | Shows the scans and groups (what each does, whether it is passive or hybrid, which external tool it uses and whether it is installed) and exits; it does not need `--target` |
| `--server {auto,llama.cpp,vllm}` | Forces the server type instead of detecting it. If the detected one differs, the report warns about the conflict and the forced one is used |
| `--declared-only` | Audits only the server of the declared `endpoint` or port: no other candidates are probed and the host's other servers are not audited. Fails if the target file declares none |

Examples:
```
mrrobotia -l
mrrobotia -t objetivo.json -s server -x cve
mrrobotia -t objetivo.json -s passive -o informes/hoy
mrrobotia -t objetivo.json -a --declared-only
mrrobotia -t objetivo.json --server vllm
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

| Group | Contents |
|---|---|
| `all` | Every scan (default) |
| `server` | `exposure`, `startup`, `cve` |
| `host` | `ssh`, `ports`, `vulns` (host security) |
| `active` | `exposure`, `ssh`, `ports` (the ones with an active part; they do **not** enable it) |
| `passive` | Like `all`, but forces skipping every active check |

A **passive** scan only observes (disk, processes, port table). A **hybrid** one always does its
passive part and, only when active probing is authorized, the part that talks to the service,
and then only with GET, HEAD and OPTIONS (plus a side-effect-free POST on llama.cpp).

**Host analysis is only done on machines with an LLM server.** `ssh`, `ports` and `vulns` are
skipped if the context contains no llama.cpp or vLLM server (identified, declared with the
`servidor` key or forced with `--server`). The report leaves a note saying why and how to force
it. The report also says which scans were requested and which were skipped, with the reason. If
a module fails, the audit goes on: an INFO finding `<module>-ERROR` is left (with only the
exception type) and the other modules run.

### Target file keys
Besides `nombre`, `autorizacion` (mandatory), `host` and `permitir_activos`:

| Keys | Read by | Purpose |
|---|---|---|
| `endpoint` | H2-ID and the others | Server URL (e.g. `http://127.0.0.1:8080/v1/chat/completions`); host, port, scheme and prefix come from it |
| `servidor` | H2-ID | `"llama.cpp"`, `"vllm"` or another name: the declared type. It is checked against what is detected (if they differ, finding `H2-ID-CONFLICTO`) |
| `exposicion` | H2-ID, H2 | `puerto`, `bind_esperado`, `proxy_autenticador`, `api_key_esperada`: what is expected of the declared server |
| `manifiesto`, `manifiesto_firmado`, `artefactos` | M2 | Hash manifest and list of `{ruta, sha256?}`. A `sha256` that is not 64 hexadecimal characters is not compared: INFO finding |
| `usuarios`, `auditoria` or `dir_logs`, `app_dir` | M3 | Files of the application around the model (read-only) |
| `ssh` | H3-SSH | `puerto` and `sshd_config` |
| `puertos` | H3-PUERTOS | `esperados` (extra legitimate ports) and `extra_peligrosos` |
| `host_trivy` | H3-HOST | `ruta` (directory to scan), `escaneres`, `severidad` |
| `herramientas` | H2-ID, H3 | Paths and timeouts per tool, e.g. `{"trivy": {"ruta": "...", "timeout": 900, "cache_dir": "..."}}`. Without it, tools are looked up in the `PATH` |

The `MRROBOTIA_TARGET` and `MRROBOTIA_ACTIVE` environment variables are alternatives to
`--target` and `--active`.

## Principles
- **Explicit authorization.** The target file declares that you have permission. Without
  `autorizacion.tengo_autorizacion = true`, the tool does not run. A non-local host needs a
  separate confirmation (`confirmo_no_local`). It is the equivalent of a pentest's consent.
- **Read-only by default.** Passive scans only observe. Network probing requires `--active`
  and `permitir_activos: true` in the target file.
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
| A1 | Legitimate user of another role: types any text (jailbreak, injection) | Nothing yet (H4 and H5, pending) |
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
│   └── objetivo.ejemplo.json
├── src/mrrobotia/
│   ├── __init__.py         # __version__
│   ├── __main__.py         # `python -m mrrobotia`
│   ├── cli.py              # command: scan selector, execution and output
│   ├── nucleo.py           # findings, authorization, report and module base class
│   ├── contexto.py         # what has been identified (servers, version, binding...)
│   ├── herramientas.py     # orchestration core for external tools
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
│       └── h3_host.py           # H3: Trivy
└── tests/                  # pytest; servidor_falso.py simulates llama.cpp and vLLM
```

## Milestones (summary)
Details, order and what each milestone extracts are in [HITOS.md](HITOS.md) (in Spanish).

| Milestone | Layer | Status |
|---|---|---|
| H0 Orchestration core | none | Done |
| H1 Artifact integrity (SHA-256) | 1 | Done |
| H2 Identification, exposure, startup and advisories | 1 | Done; llama.cpp validated with a real server, **vLLM pending validation** |
| H3 Host security (SSH, ports, Trivy) | 1 | Done; Trivy and ssh-audit only with simulated output |
| H4 Endpoint sweep | 2 | Pending (garak) |
| H5 Prompt injection and evals | 2 | Pending (promptfoo) |
| H6 Prompts and outputs do not leave the network | 2 | Pending (DeepEval) |

## Out of scope
- Extraction of secrets from process memory.
- Load generation to exhaust resources (DoS).
- Scanning or testing third-party systems.
