*Léeme en [español](README.es.md).*

# MRRobotIA: defensive posture auditor for self-hosted LLMs

A **defensive audit** (hardening) tool for self-hosted LLM servers. It first **identifies**
what it is dealing with (server, version, how it was started and on which system), adapts its
checks to what it found and **normalizes everything into a single report** with severities and
references to OWASP LLM Top 10 2025, MITRE ATLAS and NIST AI 600-1. When useful, it
**orchestrates well-established tools** (Julius, ssh-audit, Trivy, garak, promptfoo and DeepTeam) locally and offline: "MRRobotIA does not do the auditing; it extracts the data". The
roadmap is in [HITOS.md](HITOS.md) (in Spanish).

> The command line (options, labels, help) and the target file (`target.json` and all its keys)
> are in English. The audit report and the module messages are still in Spanish for now.

## What it checks

| Milestone · alias | Scan (`-s`) | What it looks at | Type | In `all` |
|---|---|---|---|---|
| H1 · `Real_Elliot` | `integrity` | SHA-256 of models, adapters and vector stores | Passive | Yes |
| H2 · `The_Voyeur` | `id`, `config`, `exposure`, `startup`, `cve` | Server and version, application configuration, binding, authentication, startup options, security advisories | Hybrid | Yes |
| H3 · `Magda` | `ssh`, `ports`, `vulns` | SSH hardening, unexpected host ports, vulnerabilities and secrets on disk (Trivy) | Hybrid | Yes |
| H4 · `fsociety` | `garak` | Sweep of the model with garak: jailbreak, prompt injection, system-prompt leak | Active | No |
| H5 · `White_Rose` | `promptfoo`, `deepteam` | Chatbot behaviour (system-prompt leak, injection, BOLA/BFLA), with a local judge and the network blocked | Active | No |
| H6 · `Young_Elliot` | `egress` | Does data leave the network? Outgoing channels and connections of the server | Hybrid | Yes (without `-a`, only the static part) |
| H7 · `Mr_Robot` | — | Attack simulation with verification of detection and recovery (pending) | — | — |

**Passive** scans only observe (disk, processes, port table); **hybrid** ones also talk to the service,
without changing anything, when active probing is authorized (`-a` and `allow_active: true` in the target
file); **active** ones send attacks to the model and are not part of `all`: ask for them with `-s <label> -a`.
Details of each one in the guide:
[H4](docs/GUIDE.md#h4-sweep-with-garak--s-garak),
[H5](docs/GUIDE.md#h5-chatbot-evaluation-with-promptfoo--s-promptfoo),
[H5, second engine](docs/GUIDE.md#h5-second-engine-deepteam--s-deepteam) and
[H6](docs/GUIDE.md#h6-does-data-leave-the-network--s-egress).

## Validation status

- **llama.cpp**: full profile tested against a real `llama-server` (build b11583).
- **vLLM**: validated against a real vLLM 0.33.0 on CPU (read-only requests); not validated on a GPU or with generation.
- **garak, promptfoo and DeepTeam**: run end to end against a real llama.cpp; vLLM not validated.
- **H6 (`egress`)**: validated against a real `llama-server` and a real vLLM on CPU; it sees destinations, not content (TLS).
- **Trivy**: validated for real. **ssh-audit**: installed and detected; its real scan is still pending.
- **Operating systems**: Windows 11 and Ubuntu 24.04 (WSL2).
- **A small local judge is not reliable**: the canaries are the confidence signal.

The full table is in the [guide](docs/GUIDE.md#validation-status).

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
(Julius, ssh-audit, Trivy, garak, Node.js, promptfoo and DeepTeam) are optional and installed separately; if one is missing, the
report says so and explains how to install it. MRRobotIA never installs anything by itself.
`mrrobotia --check-tools` shows which scans use each tool, whether it is installed and how to install it
on your system; the full guide, with pinned versions and checksum verification, is [docs/TOOLS.md](docs/TOOLS.md).
For garak, see [H4](docs/GUIDE.md#h4-sweep-with-garak--s-garak); for promptfoo (it needs
Node.js 22.22 or later), [H5](docs/GUIDE.md#h5-chatbot-evaluation-with-promptfoo--s-promptfoo);
for DeepTeam (a Python virtual environment),
[H5, second engine](docs/GUIDE.md#h5-second-engine-deepteam--s-deepteam).

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
mrrobotia -t target.json -s promptfoo -a     # chatbot evaluation with promptfoo (H5; active, not part of all)
mrrobotia -t target.json -s egress           # does data leave the network? (H6; -a adds canary traffic)
```

## Documentation
- [User guide](docs/GUIDE.md): validation status, target file, command options, scans and groups,
  H4, H5 (promptfoo and DeepTeam), H6, threat model, project structure, milestones and aliases.
- [External tools guide](docs/TOOLS.md): how to install and verify each one.
- [HITOS.md](HITOS.md): roadmap (in Spanish).
- [CHANGELOG.md](CHANGELOG.md): changes per version (in Spanish).
- [LICENSE](LICENSE): license.

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

## Out of scope
- Extraction of secrets from process memory.
- Load generation to exhaust resources (DoS).
- Scanning or testing third-party systems.
