# Instalación de las herramientas externas

MRRobotIA **orquesta** herramientas de seguridad ya consolidadas y **no instala nada por su cuenta**: es una herramienta de seguridad y descargar binarios sola sería un riesgo de cadena de suministro. Esta guía dice cómo instalar cada una de forma aislada, con la versión fijada y, cuando el proyecto publica sumas de comprobación, verificando la integridad. Todas son opcionales: si falta una, el informe lo dice (INFO) y explica cómo instalarla.

## Comprobar el entorno

```
mrrobotia --check-tools
mrrobotia --check-tools -t target.json
mrrobotia --check-tools --os linux
```

No necesita objetivo ni red. Para cada herramienta muestra qué escaneos la usan, si está (ruta y versión), la versión mínima, y la forma exacta de instalarla en tu sistema. Con `-t` respeta las rutas `tools.<nombre>.path` del fichero objetivo; con `--os windows|linux|macos` enseña las instrucciones de otro sistema. Las instrucciones del informe, las de este comando y las de esta guía salen del mismo catálogo (`src/mrrobotia/instalacion.py`).

## Convenciones

- Las herramientas se instalan en una carpeta propia (`%LOCALAPPDATA%\MRRobotIA\tools` en Windows, `~/.local/mrrobotia-tools` en Linux y macOS); no hace falta ser administrador. Cambia la primera línea de cada bloque (`$Destino` / `DESTINO`) si prefieres otra carpeta (por ejemplo, otro disco).
- **Cómo apuntar MRRobotIA a una herramienta** que no está en el `PATH`: en el fichero objetivo,
  ```json
  "tools": {"trivy": {"path": "C:/ruta/absoluta/trivy.exe", "cache_dir": "D:/trivy-cache", "timeout": 900}}
  ```
  (`path`, `timeout` y, solo para Trivy, `cache_dir`). Sin ese bloque se busca en el `PATH`.
- **Estado de la validación:** las órdenes de Windows están ejecutadas de verdad. Las de Linux y macOS se han escrito a partir de la documentación oficial y de los ficheros de cada página de versiones, y **no se han ejecutado** en esos sistemas.
- Las versiones fijadas son las probadas con MRRobotIA. Las instalaciones sin fijar (winget, apt, brew, snap) quedan como alternativa.
- La verificación es una suma SHA-256 contra el fichero que publica el propio proyecto. Es una comprobación de integridad de la descarga, no una prueba de autoría: Trivy y Julius publican además paquetes Sigstore (`.sigstore.json`) para quien quiera verificar la firma con `cosign`.

## Trivy (versión fijada: 0.76.2)

**Para qué la usa MRRobotIA:** Escanea una carpeta local (dependencias vulnerables, malas configuraciones y secretos) en H3 (escaneo `vulns`). La carpeta se declara en `trivy_host.path` y solo se lee.

### Instalación

**Windows (PowerShell 5.1 o superior), recomendada: Official binary with SHA-256 verification** ([fuente](https://github.com/aquasecurity/trivy/releases/tag/v0.76.2))

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

Ejecutable resultante: `%LOCALAPPDATA%\MRRobotIA\tools\bin\trivy.exe`

**Windows (PowerShell 5.1 o superior), alternativa: winget (version not pinned)** ([fuente](https://trivy.dev/latest/getting-started/installation/))

```powershell
winget install AquaSecurity.Trivy
```

**Linux, recomendada: Official binary with SHA-256 verification (x86-64; on ARM use Linux-ARM64)** ([fuente](https://github.com/aquasecurity/trivy/releases/tag/v0.76.2))

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

Ejecutable resultante: `$HOME/.local/mrrobotia-tools/bin/trivy`

**Linux, alternativa: Official apt repository (Debian/Ubuntu; system-wide, version not pinned)** ([fuente](https://trivy.dev/latest/getting-started/installation/))

```bash
sudo apt-get install wget gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

Ejecutable resultante: `/usr/bin/trivy`

**macOS, recomendada: Official binary with SHA-256 verification (Intel; on Apple Silicon use macOS-ARM64)** ([fuente](https://github.com/aquasecurity/trivy/releases/tag/v0.76.2))

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

Ejecutable resultante: `$HOME/.local/mrrobotia-tools/bin/trivy`

**macOS, alternativa: Homebrew (version not pinned)** ([fuente](https://trivy.dev/latest/getting-started/installation/))

```bash
brew install trivy
```

### Verificación

```
trivy --version
```

SHA-256 del archivo frente a `trivy_<versión>_checksums.txt` (el bloque lo hace). Cada archivo lleva además un paquete Sigstore (`.sigstore.json`).

### Datos y cachés

Trivy guarda su **base de datos de vulnerabilidades en una caché**: por defecto `%LOCALAPPDATA%\trivy` (Windows), `~/.cache/trivy` (Linux) o `~/Library/Caches/trivy` (macOS). **Pesa: unos 134 MB de descarga y unos 1,7 GB descomprimida** (medido con la 0.76.2). MRRobotIA escanea **sin red** (`--skip-db-update --offline-scan`), así que la base se descarga antes con la última orden del bloque de instalación y conviene refrescarla de vez en cuando. Se mueve con la variable `TRIVY_CACHE_DIR`, con `--cache-dir` o con `tools.trivy.cache_dir` en el objetivo.

### Apuntar MRRobotIA a ella

`tools.trivy.path` y `tools.trivy.cache_dir` en el objetivo, más `trivy_host.path` (carpeta que se escanea).

## ssh-audit (versión fijada: 3.9.0)

**Para qué la usa MRRobotIA:** Audita el servicio SSH (algoritmos, versión, CVE) en la parte activa de H3 (escaneo `ssh`); requiere `-a` y `allow_active=true`. Necesita Python 3.10 o superior.

### Instalación

**Windows (PowerShell 5.1 o superior), recomendada: pip in its own virtual environment (pinned version)** ([fuente](https://github.com/jtesta/ssh-audit#readme))

```powershell
$Destino = "$env:LOCALAPPDATA\MRRobotIA\tools"
python -m venv "$Destino\venvs\ssh-audit"
& "$Destino\venvs\ssh-audit\Scripts\python.exe" -m pip install ssh-audit==3.9.0
```

Ejecutable resultante: `%LOCALAPPDATA%\MRRobotIA\tools\venvs\ssh-audit\Scripts\ssh-audit.exe`

**Windows (PowerShell 5.1 o superior), alternativa: ssh-audit.exe from the releases page (pinned version)** ([fuente](https://github.com/jtesta/ssh-audit/releases/tag/v3.9.0))

```powershell
Download ssh-audit.exe from https://github.com/jtesta/ssh-audit/releases/tag/v3.9.0
Check its SHA-256 (the release page shows it) and its signature ssh-audit.exe.sig with the project keys
```

**Linux, recomendada: pip in its own virtual environment (pinned version)** ([fuente](https://github.com/jtesta/ssh-audit#readme))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
python3 -m venv "$DESTINO/venvs/ssh-audit"
"$DESTINO/venvs/ssh-audit/bin/python" -m pip install ssh-audit==3.9.0
```

Ejecutable resultante: `$HOME/.local/mrrobotia-tools/venvs/ssh-audit/bin/ssh-audit`

**Linux, alternativa: snap (version not pinned)** ([fuente](https://github.com/jtesta/ssh-audit#readme))

```bash
snap install ssh-audit
```

**macOS, recomendada: pip in its own virtual environment (pinned version)** ([fuente](https://github.com/jtesta/ssh-audit#readme))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
python3 -m venv "$DESTINO/venvs/ssh-audit"
"$DESTINO/venvs/ssh-audit/bin/python" -m pip install ssh-audit==3.9.0
```

Ejecutable resultante: `$HOME/.local/mrrobotia-tools/venvs/ssh-audit/bin/ssh-audit`

**macOS, alternativa: Homebrew (version not pinned; formula at formulae.brew.sh/formula/ssh-audit)** ([fuente](https://github.com/jtesta/ssh-audit#readme))

```bash
brew install ssh-audit
```

### Verificación

```
ssh-audit -h
```
(ssh-audit no acepta `--version`; su cabecera `# ssh-audit vX.Y.Z` sale con `-h`, y MRRobotIA la lee así.)

pip descarga de PyPI por HTTPS con la versión fijada; PyPI no publica una suma aparte. Para `ssh-audit.exe`, la página de la versión muestra su SHA-256 y publica una firma (`ssh-audit.exe.sig`) del proyecto.

### Datos y cachés

No guarda datos ni cachés.

### Apuntar MRRobotIA a ella

`tools.ssh-audit.path` apuntando a `ssh-audit.exe` (Windows) o a `bin/ssh-audit` del entorno virtual.

## garak (versión fijada: 0.17.1)

**Para qué la usa MRRobotIA:** Barre el endpoint del modelo con cientos de ataques (jailbreak, inyección de prompt, fugas) en H4 (escaneo `garak`, fuera de `all`; requiere `-a` y `allow_active=true`). Necesita Python 3.11 o superior (la documentación de garak indica 3.11 a 3.14) y MRRobotIA exige la 0.17.0 o posterior.

### Instalación

**Windows (PowerShell 5.1 o superior), recomendada: pip in its own virtual environment (pinned version; CPU-only PyTorch)** ([fuente](https://github.com/NVIDIA/garak#installation))

```powershell
$Destino = "$env:LOCALAPPDATA\MRRobotIA\tools"
python -m venv "$Destino\venvs\garak"
& "$Destino\venvs\garak\Scripts\python.exe" -m pip install garak==0.17.1 --extra-index-url https://download.pytorch.org/whl/cpu
```

Ejecutable resultante: `%LOCALAPPDATA%\MRRobotIA\tools\venvs\garak\Scripts\garak.exe`

**Linux, recomendada: pip in its own virtual environment (pinned version; CPU-only PyTorch)** ([fuente](https://github.com/NVIDIA/garak#installation))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
python3 -m venv "$DESTINO/venvs/garak"
"$DESTINO/venvs/garak/bin/python" -m pip install garak==0.17.1 --extra-index-url https://download.pytorch.org/whl/cpu
```

Ejecutable resultante: `$HOME/.local/mrrobotia-tools/venvs/garak/bin/garak`

**macOS, recomendada: pip in its own virtual environment (pinned version)** ([fuente](https://github.com/NVIDIA/garak#installation))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
python3 -m venv "$DESTINO/venvs/garak"
"$DESTINO/venvs/garak/bin/python" -m pip install garak==0.17.1
```

Ejecutable resultante: `$HOME/.local/mrrobotia-tools/venvs/garak/bin/garak`

### Verificación

```
garak --version
```

pip descarga de PyPI por HTTPS con la versión fijada; PyPI no publica una suma aparte.

### Datos y cachés

MRRobotIA redirige las carpetas XDG de garak (registros y cachés) a `<prefijo de -o>_garak/home/`: no escribe en el directorio personal. Con `garak.offline` (por defecto) no descarga modelos. PyTorch solo CPU pesa mucho menos que la versión con GPU.

### Apuntar MRRobotIA a ella

`tools.garak.path` apuntando a `Scripts\garak.exe` (Windows) o a `bin/garak` del entorno virtual.

## Julius (versión fijada: 1.6.0)

**Para qué la usa MRRobotIA:** Reconoce más servicios LLM por sus sondas en H2 (escaneo `id`). **Optativa**: sin ella H2 reconoce llama.cpp y vLLM con sus perfiles y trata el resto como genérico.

### Instalación

**Windows (PowerShell 5.1 o superior), recomendada: Official binary with SHA-256 verification** ([fuente](https://github.com/praetorian-inc/julius/releases/tag/v1.6.0))

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

Ejecutable resultante: `%LOCALAPPDATA%\MRRobotIA\tools\bin\julius.exe`

**Windows (PowerShell 5.1 o superior), alternativa: With Go installed (builds from source)** ([fuente](https://github.com/praetorian-inc/julius/releases/tag/v1.6.0))

```powershell
go install github.com/praetorian-inc/julius/cmd/julius@v1.6.0
```

Ejecutable resultante: `%GOBIN% or %USERPROFILE%\go\bin\julius.exe`

**Linux, recomendada: Official binary with SHA-256 verification (x86-64; on ARM use linux_arm64)** ([fuente](https://github.com/praetorian-inc/julius/releases/tag/v1.6.0))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
mkdir -p "$DESTINO/bin" "$DESTINO/dl"
BASE="https://github.com/praetorian-inc/julius/releases/download/v1.6.0"
curl -fsSL -o "$DESTINO/dl/julius.tar.gz" "$BASE/julius_1.6.0_linux_amd64.tar.gz"
curl -fsSL -o "$DESTINO/dl/julius_checksums.txt" "$BASE/checksums.txt"
(cd "$DESTINO/dl" && grep "julius_1.6.0_linux_amd64.tar.gz$" julius_checksums.txt | sed "s/  .*/  julius.tar.gz/" | sha256sum -c -)
tar -xzf "$DESTINO/dl/julius.tar.gz" -C "$DESTINO/bin" julius
```

Ejecutable resultante: `$HOME/.local/mrrobotia-tools/bin/julius`

**Linux, alternativa: With Go installed (builds from source)** ([fuente](https://github.com/praetorian-inc/julius/releases/tag/v1.6.0))

```bash
go install github.com/praetorian-inc/julius/cmd/julius@v1.6.0
```

Ejecutable resultante: `$(go env GOPATH)/bin/julius`

**macOS, recomendada: Official binary with SHA-256 verification (Intel; on Apple Silicon use darwin_arm64)** ([fuente](https://github.com/praetorian-inc/julius/releases/tag/v1.6.0))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
mkdir -p "$DESTINO/bin" "$DESTINO/dl"
BASE="https://github.com/praetorian-inc/julius/releases/download/v1.6.0"
curl -fsSL -o "$DESTINO/dl/julius.tar.gz" "$BASE/julius_1.6.0_darwin_amd64.tar.gz"
curl -fsSL -o "$DESTINO/dl/julius_checksums.txt" "$BASE/checksums.txt"
(cd "$DESTINO/dl" && grep "julius_1.6.0_darwin_amd64.tar.gz$" julius_checksums.txt | sed "s/  .*/  julius.tar.gz/" | shasum -a 256 -c -)
tar -xzf "$DESTINO/dl/julius.tar.gz" -C "$DESTINO/bin" julius
```

Ejecutable resultante: `$HOME/.local/mrrobotia-tools/bin/julius`

**macOS, alternativa: With Go installed (builds from source)** ([fuente](https://github.com/praetorian-inc/julius/releases/tag/v1.6.0))

```bash
go install github.com/praetorian-inc/julius/cmd/julius@v1.6.0
```

Ejecutable resultante: `$(go env GOPATH)/bin/julius`

### Verificación

```
julius --help
```
Julius no informa de su versión.

SHA-256 del archivo frente a `checksums.txt` de la misma versión (el bloque lo hace). Esa versión también publica `checksums.txt.sigstore.json`.

### Datos y cachés

No guarda datos ni cachés.

### Apuntar MRRobotIA a ella

`tools.julius.path` en el objetivo.

## Node.js (versión fijada: 22.23.5)

**Para qué la usa MRRobotIA:** Ejecuta promptfoo en H5 (escaneo `promptfoo`). **Solo hace falta para H5**: promptfoo exige Node.js 22.22 o superior y se niega a arrancar con uno anterior; MRRobotIA lo informa como `H5-PROMPTFOO-NODE-ANTIGUO` (INFO) y no ejecuta nada.

### Instalación

**Windows (PowerShell 5.1 o superior), recomendada: Official portable zip with SHA-256 verification (no administrator rights)** ([fuente](https://nodejs.org/en/download))

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

Ejecutable resultante: `%LOCALAPPDATA%\MRRobotIA\tools\node\node-v22.23.5-win-x64\node.exe`

**Windows (PowerShell 5.1 o superior), alternativa: winget (version not pinned; it must be 22.22 or later)** ([fuente](https://nodejs.org/en/download))

```powershell
winget install OpenJS.NodeJS.LTS
```

**Linux, recomendada: Official binary with SHA-256 verification (x86-64; on ARM use linux-arm64)** ([fuente](https://nodejs.org/en/download))

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

Ejecutable resultante: `$HOME/.local/mrrobotia-tools/node/node-v22.23.5-linux-x64/bin/node`

**macOS, recomendada: Official binary with SHA-256 verification (Intel; on Apple Silicon use darwin-arm64)** ([fuente](https://nodejs.org/en/download))

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

Ejecutable resultante: `$HOME/.local/mrrobotia-tools/node/node-v22.23.5-darwin-x64/bin/node`

**macOS, alternativa: Homebrew (version not pinned; it must be 22.22 or later)** ([fuente](https://nodejs.org/en/download))

```bash
brew install node
```

### Verificación

```
node --version
```

El SHA-256 del archivo se comprueba con `SHASUMS256.txt` (el bloque lo hace). Ese fichero también está firmado (`SHASUMS256.txt.sig`). Estas órdenes no se han ejecutado: la validación instaló Node con el paquete `node` de npm.

### Datos y cachés

No guarda datos propios. El `node` que esté primero en el `PATH` es el que usa promptfoo, salvo que el objetivo declare `tools.node.path` (ver abajo): pon la carpeta descomprimida (`node.exe` o `bin/`) la primera en el `PATH`, o decláralo.

### Apuntar MRRobotIA a ella

`tools.node.path` en el objetivo, apuntando al ejecutable `node` (`node.exe` en Windows). `--check-tools` lo lee y MRRobotIA antepone su carpeta al `PATH` de cada proceso de promptfoo (la consulta de versión y la ejecución); no se añade nada más a ese entorno. Si el fichero no existe, el `PATH` no se toca y H5-PROMPTFOO informa `H5-PROMPTFOO-NODE-NO-ENCONTRADO` (INFO).


## promptfoo (versión fijada: 0.126.0)

**Para qué la usa MRRobotIA:** Evalúa el comportamiento del chatbot (fuga del system prompt, inyección de prompt directa e indirecta, fuga entre sesiones, BOLA/BFLA...) en H5 (escaneo `promptfoo`, fuera de `all`; requiere `-a` y `allow_active=true`). **Necesita Node.js 22.22 o superior** (ver arriba) y MRRobotIA exige promptfoo 0.126.0 o posterior. Siempre se ejecuta con la red bloqueada (ver [la guía](GUIA.md#h5-evaluación-del-chatbot-con-promptfoo--s-promptfoo)).

### Instalación

**Windows (PowerShell 5.1 o superior), recomendada: npm with the version pinned (needs Node.js 22.22 or later)** ([fuente](https://www.promptfoo.dev/docs/installation/))

```powershell
$Destino = "$env:LOCALAPPDATA\MRRobotIA\tools"
New-Item -ItemType Directory -Force "$Destino\promptfoo" | Out-Null
npm install promptfoo@0.126.0 --prefix "$Destino\promptfoo" --no-audit --no-fund
```

Ejecutable resultante: `%LOCALAPPDATA%\MRRobotIA\tools\promptfoo\node_modules\.bin\promptfoo.cmd`

**Linux, recomendada: npm with the version pinned (needs Node.js 22.22 or later)** ([fuente](https://www.promptfoo.dev/docs/installation/))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
mkdir -p "$DESTINO/promptfoo"
npm install promptfoo@0.126.0 --prefix "$DESTINO/promptfoo" --no-audit --no-fund
```

Ejecutable resultante: `$HOME/.local/mrrobotia-tools/promptfoo/node_modules/.bin/promptfoo`

**macOS, recomendada: npm with the version pinned (needs Node.js 22.22 or later)** ([fuente](https://www.promptfoo.dev/docs/installation/))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
mkdir -p "$DESTINO/promptfoo"
npm install promptfoo@0.126.0 --prefix "$DESTINO/promptfoo" --no-audit --no-fund
```

Ejecutable resultante: `$HOME/.local/mrrobotia-tools/promptfoo/node_modules/.bin/promptfoo`

### Verificación

```
promptfoo --version
```

npm comprueba cada paquete con el hash de integridad SHA-512 del registro; promptfoo no publica una suma aparte, por eso se fija la versión. `npm audit signatures` verifica las firmas del registro.

### Datos y cachés

MRRobotIA ejecuta promptfoo con su estado (`PROMPTFOO_CONFIG_DIR`: base de datos, caché, registros de depuración) dentro de `<prefijo de -o>_promptfoo/home/`, con la telemetría, la comprobación de versión, el compartir y la generación remota desactivados y un proxy muerto: no escribe en `~/.promptfoo` ni descarga nada. La instalación sí usa la caché de npm (`~/.npm`; se cambia con `npm_config_cache`) y ocupa unos 600 MB.

### Apuntar MRRobotIA a ella

`tools.promptfoo.path` apuntando a `node_modules/.bin/promptfoo` (Linux, macOS) o `node_modules\.bin\promptfoo.cmd` (Windows) de la carpeta de instalación.

## DeepTeam (versión fijada: 1.0.10)

**Para qué la usa MRRobotIA:** Evalúa el comportamiento del chatbot (fuga de datos personales y del system prompt, BOLA, BFLA, RBAC, SSRF, agencia excesiva...) en H5 (escaneo `deepteam`, segundo motor de H5 junto a promptfoo; fuera de `all`; requiere `-a` y `allow_active=true`). Necesita Python 3.10 a 3.13 (DeepTeam 1.0.10 exige menos de 3.14) y MRRobotIA exige la 1.0.10 o posterior, con DeepEval 4.3.4. **`sentry-sdk` es obligatorio:** DeepTeam 1.0.10 lo importa sin declararlo (fallo de empaquetado) y sin él ni siquiera se importa. Siempre se ejecuta con la red bloqueada (ver [la guía](GUIA.md#h5-segundo-motor-deepteam--s-deepteam)).

### Instalación

**Windows (PowerShell 5.1 o superior), recomendada: pip in its own virtual environment (pinned versions; Python 3.10 to 3.13)** ([fuente](https://github.com/confident-ai/deepteam#readme))

```powershell
$Destino = "$env:LOCALAPPDATA\MRRobotIA\tools"
python -m venv "$Destino\venvs\deepteam"
& "$Destino\venvs\deepteam\Scripts\python.exe" -m pip install deepeval==4.3.4 deepteam==1.0.10 sentry-sdk==2.75.0
```

Ejecutable resultante: `%LOCALAPPDATA%\MRRobotIA\tools\venvs\deepteam\Scripts\deepteam.exe`

**Linux, recomendada: pip in its own virtual environment (pinned versions; Python 3.10 to 3.13)** ([fuente](https://github.com/confident-ai/deepteam#readme))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
python3 -m venv "$DESTINO/venvs/deepteam"
"$DESTINO/venvs/deepteam/bin/python" -m pip install deepeval==4.3.4 deepteam==1.0.10 sentry-sdk==2.75.0
```

Ejecutable resultante: `$HOME/.local/mrrobotia-tools/venvs/deepteam/bin/deepteam`

**macOS, recomendada: pip in its own virtual environment (pinned versions; Python 3.10 to 3.13)** ([fuente](https://github.com/confident-ai/deepteam#readme))

```bash
DESTINO="$HOME/.local/mrrobotia-tools"
python3 -m venv "$DESTINO/venvs/deepteam"
"$DESTINO/venvs/deepteam/bin/python" -m pip install deepeval==4.3.4 deepteam==1.0.10 sentry-sdk==2.75.0
```

Ejecutable resultante: `$HOME/.local/mrrobotia-tools/venvs/deepteam/bin/deepteam`

Son unos 100 MB (84 paquetes). `tools.deepteam.path` debe apuntar al **ejecutable `deepteam`** del entorno virtual: MRRobotIA no importa DeepTeam, ejecuta su propio script con el `python` que está junto a él.

### Verificación

```
deepteam --version
```

pip descarga de PyPI por HTTPS con las versiones fijadas; PyPI no publica una suma aparte. Con `--check-tools` la consulta de versión se hace también con el bloqueo de red (sin él, DeepTeam consulta la IP pública y manda telemetría solo con importarse).

### Datos y cachés

MRRobotIA ejecuta DeepTeam con `DEEPEVAL_HOME`, el directorio personal, los temporales y el directorio de trabajo dentro de `<prefijo de -o>_deepteam/home/`, con la telemetría cortada (`DEEPEVAL_TELEMETRY_OPT_OUT=1` y `DEEPTEAM_TELEMETRY_OPT_OUT=YES`: DeepTeam solo acepta el literal `YES`), sin claves de API y con un proxy muerto: no escribe en `~/.deepeval` ni en la carpeta actual, y no manda nada. DeepEval guarda los ataques y las respuestas **en claro**: están en `raw/` y `home/`. La caché de pip solo se usa en la instalación.

### Apuntar MRRobotIA a ella

`tools.deepteam.path` apuntando a `Scripts\deepteam.exe` (Windows) o a `bin/deepteam` del entorno virtual.
