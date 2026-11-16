"""
Enumeración de procesos del host (Windows y Linux) y lectura de su entorno.

PRIVACIDAD: `Proceso.argv` contiene la línea de órdenes completa, con posibles secretos.
Solo vive el tiempo de pasarla a un perfil, que extrae lo que está en su lista blanca: no
se guarda ni se informa, y queda fuera del `repr` para que ningún registro la vuelque. Del
entorno de un proceso solo se leen las variables pedidas, y las secretas se convierten en
`True` al leerlas.

Solo biblioteca estándar, sin `shell=True` y sin lanzar nunca al llamador.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from mrrobotia.red import decodificar

TIMEOUT_POWERSHELL = 30     # s; Get-CimInstance puede tardar en equipos cargados
MAX_FICHERO_PROC = 1_000_000
MAX_METADATA = 20_000        # la versión está en las primeras líneas de METADATA

# La codificación se fija porque, si no, PowerShell escribe en la página OEM de la consola.
_ORDEN_WINDOWS = ("[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
                  "Get-CimInstance Win32_Process"
                  " | Select-Object ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Json -Compress")


@dataclass
class Proceso:
    pid: int
    nombre: str
    argv: list[str] = field(default_factory=list, repr=False)
    ppid: int | None = None     # proceso padre, para agrupar un servidor con sus hijos


def trocear_linea_windows(linea):
    """Trocea una línea de órdenes de Windows con las reglas de CommandLineToArgvW, sin
    pasar por ninguna shell.

    El primer argumento (el programa) solo atiende a las comillas. En el resto, 2n barras
    seguidas de comilla son n barras y la comilla delimita; 2n+1 barras y comilla son n
    barras y una comilla literal; `""` dentro de comillas es una comilla literal.
    """
    args, i, n = [], 0, len(linea)
    while i < n and linea[i] in " \t":
        i += 1
    if i >= n:
        return args
    if linea[i] == '"':
        fin = linea.find('"', i + 1)
        fin = n if fin < 0 else fin
        args.append(linea[i + 1:fin])
        i = fin + 1
    else:
        j = i
        while j < n and linea[j] not in " \t":
            j += 1
        args.append(linea[i:j])
        i = j

    while True:
        while i < n and linea[i] in " \t":
            i += 1
        if i >= n:
            return args
        actual, entre_comillas = [], False
        while i < n:
            c = linea[i]
            if c == "\\":
                j = i
                while j < n and linea[j] == "\\":
                    j += 1
                barras = j - i
                if j < n and linea[j] == '"':
                    actual.append("\\" * (barras // 2))
                    if barras % 2:
                        actual.append('"')
                        j += 1
                else:
                    actual.append("\\" * barras)
                i = j
            elif c == '"':
                if entre_comillas and i + 1 < n and linea[i + 1] == '"':
                    actual.append('"')
                    i += 2
                else:
                    entre_comillas = not entre_comillas
                    i += 1
            elif c in " \t" and not entre_comillas:
                break
            else:
                actual.append(c)
                i += 1
        args.append("".join(actual))


def procesos_desde_json(salida):
    """Interpreta la salida (bytes) de `Get-CimInstance ... | ConvertTo-Json`. Una línea de
    órdenes ausente (null: procesos de otros usuarios) deja `argv` solo con el nombre, que
    basta para reconocer el servidor aunque no sus opciones."""
    texto = decodificar(salida).lstrip("﻿").strip()
    if not texto:
        return []
    try:
        datos = json.loads(texto)
    except ValueError:
        return []
    if isinstance(datos, dict):         # ConvertTo-Json no hace lista si hay un solo objeto
        datos = [datos]
    if not isinstance(datos, list):
        return []
    lista = []
    for d in datos:
        if not isinstance(d, dict) or not isinstance(d.get("ProcessId"), int):
            continue
        nombre = str(d.get("Name") or "")
        linea = d.get("CommandLine")
        argv = trocear_linea_windows(linea) if isinstance(linea, str) else []
        padre = d.get("ParentProcessId")
        lista.append(Proceso(d["ProcessId"], nombre, argv or ([nombre] if nombre else []),
                             padre if isinstance(padre, int) and not isinstance(padre, bool) else None))
    return lista


def _powershell():
    """Ruta absoluta de PowerShell si se conoce (evita ejecutar un homónimo del directorio
    actual); si no, se confía en el PATH."""
    raiz = os.environ.get("SystemRoot")
    if raiz:
        ruta = Path(raiz) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if ruta.exists():
            return str(ruta)
    return "powershell"


def enumerar_windows():
    proc = subprocess.run(
        [_powershell(), "-NoProfile", "-NonInteractive", "-Command", _ORDEN_WINDOWS],
        capture_output=True, timeout=TIMEOUT_POWERSHELL)
    return procesos_desde_json(proc.stdout)


def enumerar_linux(raiz="/proc"):
    """Lee `<raiz>/<pid>/cmdline`. Los hilos del núcleo tienen el fichero vacío."""
    lista = []
    for entrada in os.listdir(raiz):
        if not entrada.isdigit():
            continue
        try:
            with open(os.path.join(raiz, entrada, "cmdline"), "rb") as f:
                datos = f.read(MAX_FICHERO_PROC)
        except OSError:                 # terminó mientras se recorría, o sin permiso
            continue
        argv = [decodificar(a) for a in datos.rstrip(b"\0").split(b"\0") if a]
        if argv:
            argv[0] = argv[0].strip()   # los títulos de setproctitle dejan relleno
            lista.append(Proceso(int(entrada), os.path.basename(argv[0]), argv, _padre_linux(raiz, entrada)))
    return lista


def _padre_linux(raiz, entrada):
    """PPID de `<raiz>/<pid>/stat`, o None. El nombre del proceso va entre paréntesis y puede
    llevar espacios y paréntesis: se busca el último «)»."""
    try:
        with open(os.path.join(raiz, entrada, "stat"), "rb") as f:
            datos = f.read(4096)
        campos = datos[datos.rindex(b")") + 1:].split()
        return int(campos[1])
    except (OSError, ValueError, IndexError):
        return None


def descendientes(lista, pid):
    """PIDs de todos los procesos de `lista` que cuelgan de `pid` (hijos, nietos...). Se recorre
    desde los hijos y no desde los padres, así un ciclo en una tabla corrupta no cuelga el programa."""
    hijos = {}
    for p in lista:
        if p.ppid is not None:
            hijos.setdefault(p.ppid, []).append(p.pid)
    vistos, pendientes = set(), list(hijos.get(pid, ()))
    while pendientes:
        actual = pendientes.pop()
        if actual in vistos or actual == pid:
            continue
        vistos.add(actual)
        pendientes.extend(hijos.get(actual, ()))
    return vistos


def version_de_paquete(argv0, paquete):
    """Versión instalada de `paquete` en el entorno virtual del ejecutable `argv0`, leída del
    `METADATA` de su `*.dist-info`. Solo lectura de ficheros locales; nada de red ni de importar
    código. None si `argv0` no es una ruta absoluta dentro de un entorno virtual o no hay metadatos."""
    try:
        ruta = Path(argv0)
        if not ruta.is_absolute():
            return None
        for raiz in ruta.parents:
            if (raiz / "pyvenv.cfg").is_file():
                break
        else:
            return None
        nombre = paquete.lower().replace("-", "_")
        for lib in (*raiz.glob("lib/python*/site-packages"), raiz / "Lib" / "site-packages"):
            for info in sorted(lib.glob(f"{nombre}-*.dist-info")):
                with open(info / "METADATA", "rb") as f:
                    for linea in f.read(MAX_METADATA).splitlines():
                        if linea.startswith(b"Version:"):
                            return decodificar(linea[8:]).strip()
    except (OSError, ValueError):
        pass
    return None


def enumerar():
    """Procesos del host. Nunca lanza: si falla o el SO no está soportado, []."""
    try:
        if os.name == "nt":
            return enumerar_windows()
        if sys.platform.startswith("linux"):
            return enumerar_linux()
    except Exception:
        pass
    return []


def leer_entorno(pid, variables, raiz="/proc"):
    """Variables de la tabla `variables` (nombre -> ¿secreta?) presentes en el entorno del
    proceso. Una secreta se guarda como True, jamás su valor. {} si no es legible: solo
    existe en Linux y solo para el propietario del proceso o root."""
    try:
        with open(os.path.join(raiz, str(int(pid)), "environ"), "rb") as f:
            datos = f.read(MAX_FICHERO_PROC)
    except (OSError, ValueError):
        return {}
    resultado = {}
    for entrada in datos.split(b"\0"):
        nombre, igual, valor = entrada.partition(b"=")
        clave = decodificar(nombre)
        if igual and clave in variables:
            resultado[clave] = True if variables[clave] else decodificar(valor)
    return resultado


def entorno_legible(pid, raiz="/proc"):
    """¿Se puede leer el entorno del proceso? Distingue «no hay ninguna de esas variables» de
    «no se ha podido mirar», que `leer_entorno` devuelve igual: `{}`."""
    try:
        with open(os.path.join(raiz, str(int(pid)), "environ"), "rb"):
            return True
    except (OSError, ValueError):
        return False
