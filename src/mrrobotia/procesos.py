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

# La codificación se fija porque, si no, PowerShell escribe en la página OEM de la consola.
_ORDEN_WINDOWS = ("[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
                  "Get-CimInstance Win32_Process"
                  " | Select-Object ProcessId,Name,CommandLine | ConvertTo-Json -Compress")


@dataclass
class Proceso:
    pid: int
    nombre: str
    argv: list[str] = field(default_factory=list, repr=False)


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
        lista.append(Proceso(d["ProcessId"], nombre, argv or ([nombre] if nombre else [])))
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
            lista.append(Proceso(int(entrada), os.path.basename(argv[0]), argv))
    return lista


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
