# Installing the external tools

MRRobotIA **orchestrates** well-established security tools and **never installs anything by itself**: it is a security tool, and downloading binaries on its own would be a supply-chain risk. This guide says how to install each one in isolation, with the version pinned and, when the project publishes checksums, verifying integrity. All of them are optional: if one is missing, the report says so (INFO) and explains how to install it.

## Check your environment

```
mrrobotia --check-tools
mrrobotia --check-tools -t target.json
mrrobotia --check-tools --os linux
```

It needs no target and no network. For each tool it shows which scans use it, whether it is installed (path and version), the minimum version, and the exact way to install it on your system. With `-t` it respects the `tools.<name>.path` entries of the target file; `--os windows|linux|macos` shows the instructions of another system. The report's instructions, this command and this guide all come from the same catalog (`src/mrrobotia/instalacion.py`).

## Conventions

- Tools go into a folder of their own (`%LOCALAPPDATA%\MRRobotIA\tools` on Windows, `~/.local/mrrobotia-tools` on Linux and macOS); no administrator rights are needed. Change the first line of each block (`$Destino` / `DESTINO`) if you prefer another folder (another disk, for instance).
- **Pointing MRRobotIA to a tool** that is not on the `PATH`: in the target file,
  ```json
  "tools": {"trivy": {"path": "C:/absolute/path/trivy.exe", "cache_dir": "D:/trivy-cache", "timeout": 900}}
  ```
  (`path`, `timeout` and, for Trivy only, `cache_dir`). Without that block the tool is looked up in the `PATH`.
- **Validation status:** the Windows commands have been run for real. The Linux and macOS ones were written from the official documentation and the files of each project's releases page, and **have not been run** on those systems.
- Pinned versions are the ones tested with MRRobotIA. Unpinned installs (winget, apt, brew, snap) are listed as alternatives.
- Verification is a SHA-256 sum against the file the project itself publishes. It checks the download's integrity, it is not proof of authorship: Trivy and Julius also publish Sigstore bundles (`.sigstore.json`) for whoever wants to verify the signature with `cosign`.

## Trivy (pinned version: 0.76.2)

**What MRRobotIA uses it for:** Scans a local folder (vulnerable dependencies, misconfigurations and secrets) in H3 (scan `vulns`). The folder is declared in `trivy_host.path` and is only read.

### Installation

**Windows (PowerShell 5.1 or later), recommended: Official binary with SHA-256 verification** ([source](https://github.com/aquasecurity/trivy/releases/tag/v0.76.2))

```powershell
$Destino = "$env:LOCALAPPDATA\MRRobotIA\tools"
New-Item -ItemType Directory -Force "$Destino\bin", "$Destino\dl" | Out-Null
$Base = "https://github.com/aquasecurity/trivy/releases/download/v0.76.2"
Invoke-WebRequest "$Base/trivy_0.76.2_windows-64bit.zip" -OutFile "$Destino\dl\trivy.zip"
Invoke-WebRequest "$Base/trivy_0.76.2_checksums.txt" -OutFile "$Destino\dl\trivy_checksums.txt"
$Esperado = ((Select-String -Path "$Destino\dl\trivy_checksums.txt" -Pattern "trivy_0.76.2_windows-64bit.zip").Line -split "\s+")[0]
if ((Get-FileHash "$Destino\dl\trivy.zip" -Algorithm SHA256).Hash -ne $Esperado.ToUpper()) { throw "SHA-256 mismatch: download discarded" }
Expand-Archive "$Destino\dl\trivy.zip" -DestinationPath "$Destino\dl\trivy" -Force
Copy-Item "$Destino\dl\trivy\trivy.exe" "$Destino\bin\trivy.exe"
& "$Destino\bin\trivy.exe" image --download-db-only --no-progress --cache-dir "$Destino\cache\trivy"
```

Resulting executable: `%LOCALAPPDATA%\MRRobotIA\tools\bin\trivy.exe`

**Windows (PowerShell 5.1 or later), alternative: winget (version not pinned)** ([source](https://trivy.dev/latest/getting-started/installation/))

```powershell
winget install AquaSecurity.Trivy
```

**Linux, recommended: Official binary with SHA-256 verification (x86-64; on ARM use Linux-ARM64)** ([source](https://github.com/aquasecurity/trivy/releases/tag/v0.76.2))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
mkdir -p "$DESTINO/bin" "$DESTINO/dl"
BASE="https://github.com/aquasecurity/trivy/releases/download/v0.76.2"
curl -fsSL -o "$DESTINO/dl/trivy.tar.gz" "$BASE/trivy_0.76.2_Linux-64bit.tar.gz"
curl -fsSL -o "$DESTINO/dl/trivy_checksums.txt" "$BASE/trivy_0.76.2_checksums.txt"
(cd "$DESTINO/dl" && grep "trivy_0.76.2_Linux-64bit.tar.gz$" trivy_checksums.txt | sed "s/  .*/  trivy.tar.gz/" | sha256sum -c -)
tar -xzf "$DESTINO/dl/trivy.tar.gz" -C "$DESTINO/bin" trivy
"$DESTINO/bin/trivy" image --download-db-only --no-progress --cache-dir "$DESTINO/cache/trivy"
```

Resulting executable: `$HOME/.local/mrrobotia-tools/bin/trivy`

**Linux, alternative: Official apt repository (Debian/Ubuntu; system-wide, version not pinned)** ([source](https://trivy.dev/latest/getting-started/installation/))

```bash
sudo apt-get install wget gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

Resulting executable: `/usr/bin/trivy`

**macOS, recommended: Official binary with SHA-256 verification (Intel; on Apple Silicon use macOS-ARM64)** ([source](https://github.com/aquasecurity/trivy/releases/tag/v0.76.2))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
mkdir -p "$DESTINO/bin" "$DESTINO/dl"
BASE="https://github.com/aquasecurity/trivy/releases/download/v0.76.2"
curl -fsSL -o "$DESTINO/dl/trivy.tar.gz" "$BASE/trivy_0.76.2_macOS-64bit.tar.gz"
curl -fsSL -o "$DESTINO/dl/trivy_checksums.txt" "$BASE/trivy_0.76.2_checksums.txt"
(cd "$DESTINO/dl" && grep "trivy_0.76.2_macOS-64bit.tar.gz$" trivy_checksums.txt | sed "s/  .*/  trivy.tar.gz/" | shasum -a 256 -c -)
tar -xzf "$DESTINO/dl/trivy.tar.gz" -C "$DESTINO/bin" trivy
"$DESTINO/bin/trivy" image --download-db-only --no-progress --cache-dir "$DESTINO/cache/trivy"
```

Resulting executable: `$HOME/.local/mrrobotia-tools/bin/trivy`

**macOS, alternative: Homebrew (version not pinned)** ([source](https://trivy.dev/latest/getting-started/installation/))

```bash
brew install trivy
```

### Verification

```
trivy --version
```

SHA-256 of the archive against `trivy_<version>_checksums.txt` (the block does it). Each archive also has a Sigstore bundle (`.sigstore.json`).

### Data and caches

Trivy keeps its **vulnerability database in a cache**: `%LOCALAPPDATA%\trivy` by default (Windows), `~/.cache/trivy` (Linux) or `~/Library/Caches/trivy` (macOS). **It is big: about 134 MB to download and about 1.7 GB once extracted** (measured with 0.76.2). MRRobotIA scans **without network** (`--skip-db-update --offline-scan`), so the database is downloaded beforehand with the last command of the install block, and should be refreshed from time to time. Move it with the `TRIVY_CACHE_DIR` variable, `--cache-dir` or `tools.trivy.cache_dir` in the target file.

### Pointing MRRobotIA to it

`tools.trivy.path` and `tools.trivy.cache_dir` in the target file, plus `trivy_host.path` (folder to scan).

## ssh-audit (pinned version: 3.9.0)

**What MRRobotIA uses it for:** Audits the SSH service (algorithms, version, CVEs) in the active part of H3 (scan `ssh`); it needs `-a` and `allow_active=true`. Needs Python 3.10 or later.

### Installation

**Windows (PowerShell 5.1 or later), recommended: pip in its own virtual environment (pinned version)** ([source](https://github.com/jtesta/ssh-audit#readme))

```powershell
$Destino = "$env:LOCALAPPDATA\MRRobotIA\tools"
python -m venv "$Destino\venvs\ssh-audit"
& "$Destino\venvs\ssh-audit\Scripts\python.exe" -m pip install ssh-audit==3.9.0
```

Resulting executable: `%LOCALAPPDATA%\MRRobotIA\tools\venvs\ssh-audit\Scripts\ssh-audit.exe`

**Windows (PowerShell 5.1 or later), alternative: ssh-audit.exe from the releases page (pinned version)** ([source](https://github.com/jtesta/ssh-audit/releases/tag/v3.9.0))

```powershell
Download ssh-audit.exe from https://github.com/jtesta/ssh-audit/releases/tag/v3.9.0
Check its SHA-256 (the release page shows it) and its signature ssh-audit.exe.sig with the project keys
```

**Linux, recommended: pip in its own virtual environment (pinned version)** ([source](https://github.com/jtesta/ssh-audit#readme))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
python3 -m venv "$DESTINO/venvs/ssh-audit"
"$DESTINO/venvs/ssh-audit/bin/python" -m pip install ssh-audit==3.9.0
```

Resulting executable: `$HOME/.local/mrrobotia-tools/venvs/ssh-audit/bin/ssh-audit`

**Linux, alternative: snap (version not pinned)** ([source](https://github.com/jtesta/ssh-audit#readme))

```bash
snap install ssh-audit
```

**macOS, recommended: pip in its own virtual environment (pinned version)** ([source](https://github.com/jtesta/ssh-audit#readme))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
python3 -m venv "$DESTINO/venvs/ssh-audit"
"$DESTINO/venvs/ssh-audit/bin/python" -m pip install ssh-audit==3.9.0
```

Resulting executable: `$HOME/.local/mrrobotia-tools/venvs/ssh-audit/bin/ssh-audit`

**macOS, alternative: Homebrew (version not pinned; formula at formulae.brew.sh/formula/ssh-audit)** ([source](https://github.com/jtesta/ssh-audit#readme))

```bash
brew install ssh-audit
```

### Verification

```
ssh-audit -h
```
(ssh-audit does not accept `--version`; its header `# ssh-audit vX.Y.Z` is printed by `-h`, and that is how MRRobotIA reads it.)

pip downloads from PyPI over HTTPS with the version pinned; PyPI publishes no separate checksum. For `ssh-audit.exe`, the release page shows its SHA-256 and publishes a project signature (`ssh-audit.exe.sig`).

### Data and caches

It stores no data or caches.

### Pointing MRRobotIA to it

`tools.ssh-audit.path` pointing to `ssh-audit.exe` (Windows) or `bin/ssh-audit` of the virtual environment.

## garak (pinned version: 0.17.1)

**What MRRobotIA uses it for:** Sweeps the model endpoint with hundreds of attacks (jailbreak, prompt injection, leaks) in H4 (scan `garak`, not part of `all`; it needs `-a` and `allow_active=true`). Needs Python 3.11 or later (garak's documentation says 3.11 to 3.14) and MRRobotIA requires 0.17.0 or later.

### Installation

**Windows (PowerShell 5.1 or later), recommended: pip in its own virtual environment (pinned version; CPU-only PyTorch)** ([source](https://github.com/NVIDIA/garak#installation))

```powershell
$Destino = "$env:LOCALAPPDATA\MRRobotIA\tools"
python -m venv "$Destino\venvs\garak"
& "$Destino\venvs\garak\Scripts\python.exe" -m pip install garak==0.17.1 --extra-index-url https://download.pytorch.org/whl/cpu
```

Resulting executable: `%LOCALAPPDATA%\MRRobotIA\tools\venvs\garak\Scripts\garak.exe`

**Linux, recommended: pip in its own virtual environment (pinned version; CPU-only PyTorch)** ([source](https://github.com/NVIDIA/garak#installation))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
python3 -m venv "$DESTINO/venvs/garak"
"$DESTINO/venvs/garak/bin/python" -m pip install garak==0.17.1 --extra-index-url https://download.pytorch.org/whl/cpu
```

Resulting executable: `$HOME/.local/mrrobotia-tools/venvs/garak/bin/garak`

**macOS, recommended: pip in its own virtual environment (pinned version)** ([source](https://github.com/NVIDIA/garak#installation))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
python3 -m venv "$DESTINO/venvs/garak"
"$DESTINO/venvs/garak/bin/python" -m pip install garak==0.17.1
```

Resulting executable: `$HOME/.local/mrrobotia-tools/venvs/garak/bin/garak`

### Verification

```
garak --version
```

pip downloads from PyPI over HTTPS with the version pinned; PyPI publishes no separate checksum.

### Data and caches

MRRobotIA redirects garak's XDG folders (logs and caches) to `<-o prefix>_garak/home/`: it writes nothing in the home directory. With `garak.offline` (the default) it downloads no models. CPU-only PyTorch is much smaller than the GPU build.

### Pointing MRRobotIA to it

`tools.garak.path` pointing to `Scripts\garak.exe` (Windows) or `bin/garak` of the virtual environment.

## Julius (pinned version: 1.6.0)

**What MRRobotIA uses it for:** Recognizes more LLM services with its probes in H2 (scan `id`). **Optional**: without it, H2 recognizes llama.cpp and vLLM with its profiles and treats the rest as generic.

### Installation

**Windows (PowerShell 5.1 or later), recommended: Official binary with SHA-256 verification** ([source](https://github.com/praetorian-inc/julius/releases/tag/v1.6.0))

```powershell
$Destino = "$env:LOCALAPPDATA\MRRobotIA\tools"
New-Item -ItemType Directory -Force "$Destino\bin", "$Destino\dl" | Out-Null
$Base = "https://github.com/praetorian-inc/julius/releases/download/v1.6.0"
Invoke-WebRequest "$Base/julius_1.6.0_windows_amd64.zip" -OutFile "$Destino\dl\julius.zip"
Invoke-WebRequest "$Base/checksums.txt" -OutFile "$Destino\dl\julius_checksums.txt"
$Esperado = ((Select-String -Path "$Destino\dl\julius_checksums.txt" -Pattern "julius_1.6.0_windows_amd64.zip").Line -split "\s+")[0]
if ((Get-FileHash "$Destino\dl\julius.zip" -Algorithm SHA256).Hash -ne $Esperado.ToUpper()) { throw "SHA-256 mismatch: download discarded" }
Expand-Archive "$Destino\dl\julius.zip" -DestinationPath "$Destino\dl\julius" -Force
Copy-Item "$Destino\dl\julius\julius.exe" "$Destino\bin\julius.exe"
```

Resulting executable: `%LOCALAPPDATA%\MRRobotIA\tools\bin\julius.exe`

**Windows (PowerShell 5.1 or later), alternative: With Go installed (builds from source)** ([source](https://github.com/praetorian-inc/julius/releases/tag/v1.6.0))

```powershell
go install github.com/praetorian-inc/julius/cmd/julius@v1.6.0
```

Resulting executable: `%GOBIN% or %USERPROFILE%\go\bin\julius.exe`

**Linux, recommended: Official binary with SHA-256 verification (x86-64; on ARM use linux_arm64)** ([source](https://github.com/praetorian-inc/julius/releases/tag/v1.6.0))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
mkdir -p "$DESTINO/bin" "$DESTINO/dl"
BASE="https://github.com/praetorian-inc/julius/releases/download/v1.6.0"
curl -fsSL -o "$DESTINO/dl/julius.tar.gz" "$BASE/julius_1.6.0_linux_amd64.tar.gz"
curl -fsSL -o "$DESTINO/dl/julius_checksums.txt" "$BASE/checksums.txt"
(cd "$DESTINO/dl" && grep "julius_1.6.0_linux_amd64.tar.gz$" julius_checksums.txt | sed "s/  .*/  julius.tar.gz/" | sha256sum -c -)
tar -xzf "$DESTINO/dl/julius.tar.gz" -C "$DESTINO/bin" julius
```

Resulting executable: `$HOME/.local/mrrobotia-tools/bin/julius`

**Linux, alternative: With Go installed (builds from source)** ([source](https://github.com/praetorian-inc/julius/releases/tag/v1.6.0))

```bash
go install github.com/praetorian-inc/julius/cmd/julius@v1.6.0
```

Resulting executable: `$(go env GOPATH)/bin/julius`

**macOS, recommended: Official binary with SHA-256 verification (Intel; on Apple Silicon use darwin_arm64)** ([source](https://github.com/praetorian-inc/julius/releases/tag/v1.6.0))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
mkdir -p "$DESTINO/bin" "$DESTINO/dl"
BASE="https://github.com/praetorian-inc/julius/releases/download/v1.6.0"
curl -fsSL -o "$DESTINO/dl/julius.tar.gz" "$BASE/julius_1.6.0_darwin_amd64.tar.gz"
curl -fsSL -o "$DESTINO/dl/julius_checksums.txt" "$BASE/checksums.txt"
(cd "$DESTINO/dl" && grep "julius_1.6.0_darwin_amd64.tar.gz$" julius_checksums.txt | sed "s/  .*/  julius.tar.gz/" | shasum -a 256 -c -)
tar -xzf "$DESTINO/dl/julius.tar.gz" -C "$DESTINO/bin" julius
```

Resulting executable: `$HOME/.local/mrrobotia-tools/bin/julius`

**macOS, alternative: With Go installed (builds from source)** ([source](https://github.com/praetorian-inc/julius/releases/tag/v1.6.0))

```bash
go install github.com/praetorian-inc/julius/cmd/julius@v1.6.0
```

Resulting executable: `$(go env GOPATH)/bin/julius`

### Verification

```
julius --help
```
Julius does not report its version.

SHA-256 of the archive against the release's `checksums.txt` (the block does it). The release also publishes `checksums.txt.sigstore.json`.

### Data and caches

It stores no data or caches.

### Pointing MRRobotIA to it

`tools.julius.path` in the target file.

## Node.js (pinned version: 22.23.5)

**What MRRobotIA uses it for:** Runs promptfoo in H5 (scan `promptfoo`). **Only needed for H5**: promptfoo requires Node.js 22.22 or later (or 20.20 or later) and refuses to start with an older one; MRRobotIA then reports `H5-PROMPTFOO-NODE-ANTIGUO` (INFO) and runs nothing.

### Installation

**Windows (PowerShell 5.1 or later), recommended: Official portable zip with SHA-256 verification (no administrator rights)** ([source](https://nodejs.org/en/download))

```powershell
$Destino = "$env:LOCALAPPDATA\MRRobotIA\tools"
New-Item -ItemType Directory -Force "$Destino\dl", "$Destino\node" | Out-Null
$Base = "https://nodejs.org/dist/v22.23.5"
$Zip = "node-v22.23.5-win-x64.zip"
Invoke-WebRequest "$Base/$Zip" -OutFile "$Destino\dl\$Zip"
Invoke-WebRequest "$Base/SHASUMS256.txt" -OutFile "$Destino\dl\node_SHASUMS256.txt"
$Esperado = ((Select-String -Path "$Destino\dl\node_SHASUMS256.txt" -Pattern ([regex]::Escape($Zip))).Line -split "\s+")[0]
if ((Get-FileHash "$Destino\dl\$Zip" -Algorithm SHA256).Hash -ne $Esperado.ToUpper()) { throw "SHA-256 mismatch: download discarded" }
Expand-Archive "$Destino\dl\$Zip" -DestinationPath "$Destino\node" -Force
```

Resulting executable: `%LOCALAPPDATA%\MRRobotIA\tools\node\node-v22.23.5-win-x64\node.exe`

**Windows (PowerShell 5.1 or later), alternative: winget (version not pinned; it must be 22.22 or later)** ([source](https://nodejs.org/en/download))

```powershell
winget install OpenJS.NodeJS.LTS
```

**Linux, recommended: Official binary with SHA-256 verification (x86-64; on ARM use linux-arm64)** ([source](https://nodejs.org/en/download))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
mkdir -p "$DESTINO/node" "$DESTINO/dl"
BASE="https://nodejs.org/dist/v22.23.5"
FICHERO="node-v22.23.5-linux-x64.tar.xz"
curl -fsSL -o "$DESTINO/dl/$FICHERO" "$BASE/$FICHERO"
curl -fsSL -o "$DESTINO/dl/node_SHASUMS256.txt" "$BASE/SHASUMS256.txt"
(cd "$DESTINO/dl" && grep " $FICHERO$" node_SHASUMS256.txt | sha256sum -c -)
tar -xf "$DESTINO/dl/$FICHERO" -C "$DESTINO/node"
```

Resulting executable: `$HOME/.local/mrrobotia-tools/node/node-v22.23.5-linux-x64/bin/node`

**macOS, recommended: Official binary with SHA-256 verification (Intel; on Apple Silicon use darwin-arm64)** ([source](https://nodejs.org/en/download))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
mkdir -p "$DESTINO/node" "$DESTINO/dl"
BASE="https://nodejs.org/dist/v22.23.5"
FICHERO="node-v22.23.5-darwin-x64.tar.gz"
curl -fsSL -o "$DESTINO/dl/$FICHERO" "$BASE/$FICHERO"
curl -fsSL -o "$DESTINO/dl/node_SHASUMS256.txt" "$BASE/SHASUMS256.txt"
(cd "$DESTINO/dl" && grep " $FICHERO$" node_SHASUMS256.txt | shasum -a 256 -c -)
tar -xf "$DESTINO/dl/$FICHERO" -C "$DESTINO/node"
```

Resulting executable: `$HOME/.local/mrrobotia-tools/node/node-v22.23.5-darwin-x64/bin/node`

**macOS, alternative: Homebrew (version not pinned; it must be 22.22 or later)** ([source](https://nodejs.org/en/download))

```bash
brew install node
```

### Verification

```
node --version
```

The archive's SHA-256 is checked against `SHASUMS256.txt` (the block does it). The file is also signed (`SHASUMS256.txt.sig`). These commands have not been run: the validation installed Node with the `node` npm package.

### Data and caches

Stores no data of its own. Whichever `node` comes first in the `PATH` is the one promptfoo uses: put the unzipped folder (`node.exe` or `bin/`) first in the `PATH`.

### Pointing MRRobotIA to it

`tools.node.path` in the target file (only used by `--check-tools`; promptfoo itself uses the `PATH`, or the Node that its own launcher chooses).


## promptfoo (pinned version: 0.126.0)

**What MRRobotIA uses it for:** Evaluates the behaviour of the chatbot (system-prompt leak, direct and indirect prompt injection, cross-session leak, BOLA/BFLA...) in H5 (scan `promptfoo`, not part of `all`; it needs `-a` and `allow_active=true`). **Needs Node.js 22.22 or later** (see above) and MRRobotIA requires promptfoo 0.126.0 or later. It always runs with the network blocked (see the README).

### Installation

**Windows (PowerShell 5.1 or later), recommended: npm with the version pinned (needs Node.js 22.22 or later)** ([source](https://www.promptfoo.dev/docs/installation/))

```powershell
$Destino = "$env:LOCALAPPDATA\MRRobotIA\tools"
New-Item -ItemType Directory -Force "$Destino\promptfoo" | Out-Null
npm install promptfoo@0.126.0 --prefix "$Destino\promptfoo" --no-audit --no-fund
```

Resulting executable: `%LOCALAPPDATA%\MRRobotIA\tools\promptfoo\node_modules\.bin\promptfoo.cmd`

**Linux, recommended: npm with the version pinned (needs Node.js 22.22 or later)** ([source](https://www.promptfoo.dev/docs/installation/))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
mkdir -p "$DESTINO/promptfoo"
npm install promptfoo@0.126.0 --prefix "$DESTINO/promptfoo" --no-audit --no-fund
```

Resulting executable: `$HOME/.local/mrrobotia-tools/promptfoo/node_modules/.bin/promptfoo`

**macOS, recommended: npm with the version pinned (needs Node.js 22.22 or later)** ([source](https://www.promptfoo.dev/docs/installation/))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
mkdir -p "$DESTINO/promptfoo"
npm install promptfoo@0.126.0 --prefix "$DESTINO/promptfoo" --no-audit --no-fund
```

Resulting executable: `$HOME/.local/mrrobotia-tools/promptfoo/node_modules/.bin/promptfoo`

### Verification

```
promptfoo --version
```

npm checks every package against the registry's SHA-512 integrity hash; promptfoo publishes no separate checksum, so the version is pinned. `npm audit signatures` verifies the registry signatures.

### Data and caches

MRRobotIA runs promptfoo with its state (`PROMPTFOO_CONFIG_DIR`: database, cache, debug logs) inside `<-o prefix>_promptfoo/home/`, with telemetry, update check, sharing and remote generation switched off and a dead proxy: it writes nothing in `~/.promptfoo` and downloads nothing. The installation itself uses npm's cache (`~/.npm`; change it with `npm_config_cache`) and takes about 600 MB.

### Pointing MRRobotIA to it

`tools.promptfoo.path` pointing to `node_modules/.bin/promptfoo` (Linux, macOS) or `node_modules\.bin\promptfoo.cmd` (Windows) of the install folder.


## Coming soon

- **DeepEval / DeepTeam**: a second evaluation engine for H5 (not H6, which is own code and needs no tool), with the
  telemetry fully cut and a local judge.

It will be documented here when it is integrated.
