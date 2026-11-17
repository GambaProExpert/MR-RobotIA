"""
Catálogo ÚNICO de instalación de las herramientas externas de MRRobotIA.

MRRobotIA no instala nada por su cuenta: es una herramienta de seguridad y descargar binarios sola
sería un riesgo de cadena de suministro. Lo que hace es decir, con la forma exacta, cómo instalarlas.
Esa información vive SOLO aquí y la usan a la vez:

- el hallazgo INFO «<herramienta> no está instalada» (vía `herramientas.como_instalar`), y
- el comando `mrrobotia --check-tools` (vía `describir`/`informe_herramientas`).

La versión fijada, la mínima exigida y el binario de cada herramienta NO se repiten aquí: se leen de la
`Herramienta` que define cada módulo (`Herramienta.fijada`, `.exigida`, `.min_version`). Las órdenes
llevan el marcador `{version}`, que se sustituye por la versión fijada.

Las órdenes de Windows están ejecutadas de verdad (ver HITOS.md). Las de Linux y macOS se han escrito a
partir de la documentación y de los ficheros publicados en las páginas de versiones de cada proyecto
(`fuente` de cada paso); no se han ejecutado en esos sistemas.

Solo biblioteca estándar y sin importar ningún módulo de MRRobotIA (lo importan los demás).
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field

SISTEMAS = ("windows", "linux", "macos")

# URL de la guía pública (misma información, con más contexto).
GUIA = "docs/TOOLS.md (English) / docs/HERRAMIENTAS.md (español)"


@dataclass(frozen=True)
class Paso:
    """Una forma de instalar una herramienta en un sistema operativo."""
    sistema: str                    # "windows" | "linux" | "macos"
    titulo: str
    ordenes: tuple                  # líneas literales que se ejecutan en orden
    fuente: str                     # URL de la documentación o de la página de versiones
    binario: str = ""               # dónde queda el ejecutable (para tools.<n>.path)
    recomendada: bool = True
    resumen: str = ""               # una línea para el hallazgo INFO (solo la recomendada)


@dataclass(frozen=True)
class Instalable:
    nombre: str
    para_que: str                   # una frase (en inglés): qué hace MRRobotIA con ella
    pasos: tuple
    verificacion: str               # cómo comprobar la integridad, en una frase
    cache: dict = field(default_factory=dict)   # sistema -> texto de caché/datos ("*" = todos)
    nota: str = ""


# -------------------------------------------------------------------- órdenes comunes
_W_DESTINO = '$Destino = "$env:LOCALAPPDATA\\MRRobotIA\\tools"'
_L_DESTINO = 'DESTINO="$HOME/.local/mrrobotia-tools"'


def _zip_windows(proyecto, base_url, zip_, checks, exe, patron):
    """Órdenes de Windows para un .zip de GitHub con fichero de sumas SHA-256."""
    return (
        _W_DESTINO,
        'New-Item -ItemType Directory -Force "$Destino\\bin", "$Destino\\dl" | Out-Null',
        f'$Base = "{base_url}"',
        f'Invoke-WebRequest "$Base/{zip_}" -OutFile "$Destino\\dl\\{proyecto}.zip"',
        f'Invoke-WebRequest "$Base/{checks}" -OutFile "$Destino\\dl\\{proyecto}_checksums.txt"',
        f'$Esperado = ((Select-String -Path "$Destino\\dl\\{proyecto}_checksums.txt" '
        f'-Pattern "{patron}").Line -split "\\s+")[0]',
        f'if ((Get-FileHash "$Destino\\dl\\{proyecto}.zip" -Algorithm SHA256).Hash -ne $Esperado.ToUpper()) '
        '{ throw "SHA-256 mismatch: download discarded" }',
        f'Expand-Archive "$Destino\\dl\\{proyecto}.zip" -DestinationPath "$Destino\\dl\\{proyecto}" -Force',
        f'Copy-Item "$Destino\\dl\\{proyecto}\\{exe}" "$Destino\\bin\\{exe}"',
    )


def _tar_posix(proyecto, base_url, tar, checks, patron_tar, binario, hash_cmd):
    """Órdenes de Linux/macOS para un .tar.gz de GitHub con fichero de sumas SHA-256."""
    return (
        _L_DESTINO,
        'mkdir -p "$DESTINO/bin" "$DESTINO/dl"',
        f'BASE="{base_url}"',
        f'curl -fsSL -o "$DESTINO/dl/{proyecto}.tar.gz" "$BASE/{tar}"',
        f'curl -fsSL -o "$DESTINO/dl/{proyecto}_checksums.txt" "$BASE/{checks}"',
        f'(cd "$DESTINO/dl" && grep "{patron_tar}$" {proyecto}_checksums.txt | sed "s/  .*/  {proyecto}.tar.gz/" '
        f'| {hash_cmd})',
        f'tar -xzf "$DESTINO/dl/{proyecto}.tar.gz" -C "$DESTINO/bin" {binario}',
    )


def _venv_windows(nombre, instalar):
    return (
        _W_DESTINO,
        f'python -m venv "$Destino\\venvs\\{nombre}"',
        f'& "$Destino\\venvs\\{nombre}\\Scripts\\python.exe" -m pip install {instalar}',
    )


def _venv_posix(nombre, instalar):
    return (
        _L_DESTINO,
        f'python3 -m venv "$DESTINO/venvs/{nombre}"',
        f'"$DESTINO/venvs/{nombre}/bin/python" -m pip install {instalar}',
    )


_T = "https://github.com/aquasecurity/trivy/releases/download/v{version}"
_T_REL = "https://github.com/aquasecurity/trivy/releases/tag/v{version}"
_T_DOCS = "https://trivy.dev/latest/getting-started/installation/"
_J = "https://github.com/praetorian-inc/julius/releases/download/v{version}"
_J_REL = "https://github.com/praetorian-inc/julius/releases/tag/v{version}"
_S_REL = "https://github.com/jtesta/ssh-audit/releases/tag/v{version}"
_S_DOC = "https://github.com/jtesta/ssh-audit#readme"
_G_DOC = "https://github.com/NVIDIA/garak#installation"

def _bd_trivy_windows():
    return ('& "$Destino\\bin\\trivy.exe" image --download-db-only --no-progress --cache-dir "$Destino\\cache\\trivy"',)


def _bd_trivy_posix(bin_):
    return (f'{bin_} image --download-db-only --no-progress --cache-dir "$DESTINO/cache/trivy"',)


CATALOGO = {
    "trivy": Instalable(
        "trivy",
        "scans the local disk (vulnerabilities, misconfigurations and secrets) in H3 'vulns'",
        (
            Paso("windows", "Official binary with SHA-256 verification",
                 _zip_windows("trivy", _T, "trivy_{version}_windows-64bit.zip", "trivy_{version}_checksums.txt",
                              "trivy.exe", "trivy_{version}_windows-64bit.zip")
                 + _bd_trivy_windows(),
                 _T_REL, "%LOCALAPPDATA%\\MRRobotIA\\tools\\bin\\trivy.exe",
                 resumen="descarga trivy_{version}_windows-64bit.zip de " + _T_REL + ", comprueba su SHA-256 con "
                         "trivy_{version}_checksums.txt y descarga la base: trivy image --download-db-only"),
            Paso("windows", "winget (version not pinned)", ("winget install AquaSecurity.Trivy",),
                 _T_DOCS, "", False),
            Paso("linux", "Official binary with SHA-256 verification (x86-64; on ARM use Linux-ARM64)",
                 _tar_posix("trivy", _T, "trivy_{version}_Linux-64bit.tar.gz", "trivy_{version}_checksums.txt",
                            "trivy_{version}_Linux-64bit.tar.gz", "trivy", "sha256sum -c -")
                 + _bd_trivy_posix('"$DESTINO/bin/trivy"'),
                 _T_REL, "$HOME/.local/mrrobotia-tools/bin/trivy",
                 resumen="descarga trivy_{version}_Linux-64bit.tar.gz de " + _T_REL + ", comprueba su SHA-256 con "
                         "trivy_{version}_checksums.txt y descarga la base: trivy image --download-db-only"),
            Paso("linux", "Official apt repository (Debian/Ubuntu; system-wide, version not pinned)",
                 ("sudo apt-get install wget gnupg",
                  "wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor "
                  "| sudo tee /usr/share/keyrings/trivy.gpg > /dev/null",
                  'echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb '
                  'generic main" | sudo tee -a /etc/apt/sources.list.d/trivy.list',
                  "sudo apt-get update", "sudo apt-get install trivy"),
                 _T_DOCS, "/usr/bin/trivy", False),
            Paso("macos", "Official binary with SHA-256 verification (Intel; on Apple Silicon use macOS-ARM64)",
                 _tar_posix("trivy", _T, "trivy_{version}_macOS-64bit.tar.gz", "trivy_{version}_checksums.txt",
                            "trivy_{version}_macOS-64bit.tar.gz", "trivy", "shasum -a 256 -c -")
                 + _bd_trivy_posix('"$DESTINO/bin/trivy"'),
                 _T_REL, "$HOME/.local/mrrobotia-tools/bin/trivy",
                 resumen="descarga trivy_{version}_macOS-64bit.tar.gz (o macOS-ARM64) de " + _T_REL + ", comprueba su "
                         "SHA-256 con trivy_{version}_checksums.txt y descarga la base: trivy image --download-db-only"),
            Paso("macos", "Homebrew (version not pinned)", ("brew install trivy",), _T_DOCS, "", False),
        ),
        "SHA-256 of the archive against trivy_{version}_checksums.txt (published in the same release). Each "
        "archive also has a Sigstore bundle (.sigstore.json) for whoever wants to verify the signature with cosign.",
        cache={"windows": "database and caches in %LOCALAPPDATA%\\trivy by default (hundreds of MB)",
               "linux": "database and caches in ~/.cache/trivy by default (hundreds of MB)",
               "macos": "database and caches in ~/Library/Caches/trivy by default (hundreds of MB)",
               "*": "change it with the TRIVY_CACHE_DIR variable, --cache-dir or tools.trivy.cache_dir in the target "
                    "file. MRRobotIA scans WITHOUT network (--skip-db-update --offline-scan): the database must be "
                    "downloaded beforehand and refreshed from time to time"},
        nota="trivy_host.path in the target file declares the folder to scan (read-only)."),

    "ssh-audit": Instalable(
        "ssh-audit",
        "audits the SSH service (algorithms, version, CVEs) in the active part of H3 'ssh'",
        (
            Paso("windows", "pip in its own virtual environment (pinned version)",
                 _venv_windows("ssh-audit", "ssh-audit=={version}"),
                 _S_DOC, "%LOCALAPPDATA%\\MRRobotIA\\tools\\venvs\\ssh-audit\\Scripts\\ssh-audit.exe",
                 resumen="en un entorno virtual: python -m venv <carpeta> y <carpeta>/Scripts/python -m pip install "
                         "ssh-audit=={version}"),
            Paso("windows", "ssh-audit.exe from the releases page (pinned version)",
                 ("Download ssh-audit.exe from " + _S_REL, "Check its SHA-256 (the release page shows it) "
                  "and its signature ssh-audit.exe.sig with the project keys"),
                 _S_REL, "", False),
            Paso("linux", "pip in its own virtual environment (pinned version)",
                 _venv_posix("ssh-audit", "ssh-audit=={version}"),
                 _S_DOC, "$HOME/.local/mrrobotia-tools/venvs/ssh-audit/bin/ssh-audit",
                 resumen="en un entorno virtual: python3 -m venv <carpeta> y <carpeta>/bin/python -m pip install "
                         "ssh-audit=={version}"),
            Paso("linux", "snap (version not pinned)", ("snap install ssh-audit",), _S_DOC, "", False),
            Paso("macos", "pip in its own virtual environment (pinned version)",
                 _venv_posix("ssh-audit", "ssh-audit=={version}"),
                 _S_DOC, "$HOME/.local/mrrobotia-tools/venvs/ssh-audit/bin/ssh-audit",
                 resumen="en un entorno virtual: python3 -m venv <carpeta> y <carpeta>/bin/python -m pip install "
                         "ssh-audit=={version}"),
            Paso("macos", "Homebrew (version not pinned; formula at formulae.brew.sh/formula/ssh-audit)",
                 ("brew install ssh-audit",), _S_DOC, "", False),
        ),
        "pip downloads from PyPI over HTTPS with the version pinned; PyPI publishes no separate checksum. The "
        "ssh-audit.exe option does have a SHA-256 and a project signature on its releases page.",
        cache={"*": "stores no data or caches"},
        nota="Needs Python 3.10 or later. It only runs in the active part (-a and allow_active=true)."),

    "garak": Instalable(
        "garak",
        "sweeps the model endpoint with attacks (jailbreak, injection, leaks) in H4 'garak'",
        (
            Paso("windows", "pip in its own virtual environment (pinned version; CPU-only PyTorch)",
                 _venv_windows("garak", "garak=={version} --extra-index-url https://download.pytorch.org/whl/cpu"),
                 _G_DOC, "%LOCALAPPDATA%\\MRRobotIA\\tools\\venvs\\garak\\Scripts\\garak.exe",
                 resumen="en un entorno virtual con Python >= 3.11: pip install garak=={version} "
                         "--extra-index-url https://download.pytorch.org/whl/cpu"),
            Paso("linux", "pip in its own virtual environment (pinned version; CPU-only PyTorch)",
                 _venv_posix("garak", "garak=={version} --extra-index-url https://download.pytorch.org/whl/cpu"),
                 _G_DOC, "$HOME/.local/mrrobotia-tools/venvs/garak/bin/garak",
                 resumen="en un entorno virtual con Python >= 3.11: pip install garak=={version} "
                         "--extra-index-url https://download.pytorch.org/whl/cpu"),
            Paso("macos", "pip in its own virtual environment (pinned version)",
                 _venv_posix("garak", "garak=={version}"),
                 _G_DOC, "$HOME/.local/mrrobotia-tools/venvs/garak/bin/garak",
                 resumen="en un entorno virtual con Python >= 3.11: pip install garak=={version}"),
        ),
        "pip downloads from PyPI over HTTPS with the version pinned; PyPI publishes no separate checksum.",
        cache={"*": "MRRobotIA redirects garak's XDG folders (logs and caches) to <-o prefix>_garak/home/; it writes "
                    "nothing in the home directory. With garak.offline (the default) it downloads no models"},
        nota="Needs Python 3.11 or later (garak's documentation says 3.11 to 3.14). It can take hours: "
             "it is not part of 'all'."),

    "julius": Instalable(
        "julius",
        "recognizes more LLM services with its probes in H2 'id' (optional)",
        (
            Paso("windows", "Official binary with SHA-256 verification",
                 _zip_windows("julius", _J, "julius_{version}_windows_amd64.zip", "checksums.txt",
                              "julius.exe", "julius_{version}_windows_amd64.zip"),
                 _J_REL, "%LOCALAPPDATA%\\MRRobotIA\\tools\\bin\\julius.exe",
                 resumen="descarga julius_{version}_windows_amd64.zip de " + _J_REL + " y comprueba su SHA-256 con "
                         "checksums.txt (o, con Go instalado: go install "
                         "github.com/praetorian-inc/julius/cmd/julius@v{version})"),
            Paso("windows", "With Go installed (builds from source)",
                 ("go install github.com/praetorian-inc/julius/cmd/julius@v{version}",),
                 _J_REL, "%GOBIN% or %USERPROFILE%\\go\\bin\\julius.exe", False),
            Paso("linux", "Official binary with SHA-256 verification (x86-64; on ARM use linux_arm64)",
                 _tar_posix("julius", _J, "julius_{version}_linux_amd64.tar.gz", "checksums.txt",
                            "julius_{version}_linux_amd64.tar.gz", "julius", "sha256sum -c -"),
                 _J_REL, "$HOME/.local/mrrobotia-tools/bin/julius",
                 resumen="descarga julius_{version}_linux_amd64.tar.gz de " + _J_REL + " y comprueba su SHA-256 con "
                         "checksums.txt (o, con Go instalado: go install "
                         "github.com/praetorian-inc/julius/cmd/julius@v{version})"),
            Paso("linux", "With Go installed (builds from source)",
                 ("go install github.com/praetorian-inc/julius/cmd/julius@v{version}",),
                 _J_REL, "$(go env GOPATH)/bin/julius", False),
            Paso("macos", "Official binary with SHA-256 verification (Intel; on Apple Silicon use darwin_arm64)",
                 _tar_posix("julius", _J, "julius_{version}_darwin_amd64.tar.gz", "checksums.txt",
                            "julius_{version}_darwin_amd64.tar.gz", "julius", "shasum -a 256 -c -"),
                 _J_REL, "$HOME/.local/mrrobotia-tools/bin/julius",
                 resumen="descarga julius_{version}_darwin_amd64.tar.gz (o darwin_arm64) de " + _J_REL + " y comprueba "
                         "su SHA-256 con checksums.txt (o, con Go instalado: go install "
                         "github.com/praetorian-inc/julius/cmd/julius@v{version})"),
            Paso("macos", "With Go installed (builds from source)",
                 ("go install github.com/praetorian-inc/julius/cmd/julius@v{version}",),
                 _J_REL, "$(go env GOPATH)/bin/julius", False),
        ),
        "SHA-256 of the archive against checksums.txt (published in the same release). The release also has "
        "a Sigstore bundle (checksums.txt.sigstore.json) to verify the signature with cosign.",
        cache={"*": "stores no data or caches"},
        nota="Optional: without Julius, H2 recognizes llama.cpp and vLLM with its profiles and treats the rest as "
             "generic. Julius does not report its version."),
}


# --------------------------------------------------------------------- consulta
def sistema_actual():
    """«windows», «linux» o «macos» según el sistema donde corre MRRobotIA."""
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _sub(texto, version):
    return texto.replace("{version}", version or "<versión>")


def pasos(herramienta, sistema=None):
    """Pasos de instalación de la herramienta para el sistema (por defecto el actual), con la versión
    fijada ya sustituida. La recomendada va primero. Lista vacía si la herramienta no está en el catálogo."""
    ins = CATALOGO.get(herramienta.nombre)
    if ins is None:
        return []
    sistema = sistema or sistema_actual()
    v = herramienta.fijada
    sus = [Paso(p.sistema, _sub(p.titulo, v), tuple(_sub(o, v) for o in p.ordenes), _sub(p.fuente, v),
                _sub(p.binario, v), p.recomendada, _sub(p.resumen, v))
           for p in ins.pasos if p.sistema == sistema]
    return sorted(sus, key=lambda p: not p.recomendada)


def resumen(herramienta, sistema=None):
    """Una línea con la forma recomendada de instalar la herramienta en el sistema, para el hallazgo INFO.
    Sin catálogo, usa `Herramienta.instalar_con`."""
    for p in pasos(herramienta, sistema):
        if p.resumen:
            return p.resumen
    return herramienta.instalar_con


def como_apuntar(herramienta):
    """Cómo decirle a MRRobotIA dónde está la herramienta si no está en el PATH (clave del objetivo)."""
    return f'"tools": {{"{herramienta.nombre}": {{"path": "/absolute/path/to/{herramienta.binario}"}}}}'


def descripcion(nombre):
    return CATALOGO.get(nombre)
