"""
Núcleo orquestador de herramientas externas de seguridad para MRRobotIA.

MRRobotIA no reimplementa cada comprobación: ejecuta herramientas ya consolidadas
(garak, promptfoo, Trivy, DeepEval…) de forma LOCAL y OFFLINE, y normaliza su
salida a los `Hallazgo` del informe único. Este módulo es el andamiaje reutilizable
para ese patrón; todavía no integra ninguna herramienta concreta (cada hito H3–H6
aportará su propio envoltorio sobre `ModuloHerramienta`).

Principios (ver HITOS.md):
- Orquestar, no reinventar. Si la herramienta no está instalada, se emite un
  hallazgo INFORMATIVO con cómo instalarla; nunca se revienta ni se da por ejecutada.
- Todo local y offline: se invoca por `subprocess`, SIEMPRE con la orden como lista
  y NUNCA con `shell=True` (evita inyección por la shell del host).
- Sin dependencias de ejecución nuevas: solo biblioteca estándar.
- Trazabilidad: cada ejecución deja un hallazgo informativo con la versión usada,
  para que los resultados del TFG sean reproducibles (sin volcar secretos).
"""
from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field

from mrrobotia import instalacion
from mrrobotia.nucleo import Modulo, Hallazgo, Severidad

# Primer número de versión tipo "x.y" o "x.y.z" que aparezca en la salida de --version.
_RE_VERSION = re.compile(r"\d+\.\d+(?:\.\d+)?")


@dataclass(frozen=True)
class Herramienta:
    """Descripción estática de una herramienta externa de línea de órdenes.

    - `nombre`: identificador corto usado en los IDs de hallazgo y en los overrides
      del objetivo (p. ej. "garak").
    - `binario`: nombre del ejecutable que se buscará en el PATH (p. ej. "garak").
    - `version_args`: argumentos para preguntar la versión (p. ej. ("--version",)), o
      None si la herramienta no tiene forma de darla y no hay que consultarla.
    - `instalar_con`: texto de instalación de reserva; la fuente de verdad es `instalacion.CATALOGO`
      (ver `como_instalar`), que solo recurre a este campo si la herramienta no está en el catálogo.
    - `min_version`: versión mínima recomendada ("x.y[.z]") o None; por debajo se emite un aviso.
    - `exigida`: versión mínima obligatoria ("x.y[.z]") o None; el módulo se niega a ejecutarse por
      debajo (solo informativo aquí: la comprobación la hace el propio módulo).
    - `fijada`: versión con la que se ha probado y que la guía de instalación fija ("x.y[.z]") o None.
    - `refs`: marcos asociados (OWASP/ATLAS/NIST) para los hallazgos del módulo.
    - `aislar_xdg`: la herramienta escribe en las carpetas XDG del usuario (en `~`) aunque solo
      se le pida la versión (garak crea `~/.cache/garak` y `~/.config/garak`). Con True, la
      consulta de versión se hace con `XDG_*` apuntando a una carpeta temporal que se borra.
    """
    nombre: str
    binario: str
    version_args: tuple | None = ("--version",)
    instalar_con: str = ""
    min_version: str | None = None
    exigida: str | None = None
    fijada: str | None = None
    refs: dict = field(default_factory=dict)
    aislar_xdg: bool = False


@dataclass
class Deteccion:
    """Resultado de buscar la herramienta en el sistema."""
    disponible: bool
    version: str | None
    ruta: str | None
    error: str | None


@dataclass
class Resultado:
    """Resultado de ejecutar un proceso externo (nunca lanza al llamador)."""
    returncode: int | None
    stdout: str
    stderr: str
    expiro: bool
    error: str | None


def como_instalar(herramienta, sistema=None):
    """Cómo instalar la herramienta en el sistema (por defecto el actual), en una línea, más cómo apuntar
    MRRobotIA a ella si ya está fuera del PATH. Misma fuente que `mrrobotia --check-tools`."""
    return (f"{instalacion.resumen(herramienta, sistema)}. Si ya la tienes fuera del PATH, indica su ruta en "
            f"tools.{herramienta.nombre}.path del objetivo. Detalle por sistema: mrrobotia --check-tools")


def _extraer_version(texto):
    """Primer 'x.y' o 'x.y.z' que aparezca en el texto; None si no hay ninguno."""
    m = _RE_VERSION.search(texto or "")
    return m.group(0) if m else None


def _consultar_version(herramienta, ruta, env):
    proc = subprocess.run(
        [ruta, *herramienta.version_args],
        capture_output=True, text=True, errors="replace", timeout=30, env=env)
    return _extraer_version((proc.stdout or "") + "\n" + (proc.stderr or ""))


def detectar(herramienta, overrides=None, env=None):
    """Busca la herramienta y, si está, consulta su versión.

    La ruta efectiva es `overrides[nombre]["path"]` si existe; si no, lo que
    devuelva `shutil.which(binario)`. Nunca lanza: si el binario está en disco
    pero falla la consulta de versión, sigue considerándose DISPONIBLE (con
    `version=None` y el tipo de error), porque existe y podrá ejecutarse.

    `env` es el entorno del proceso que consulta la versión (por defecto, el actual). Si no se da
    y la herramienta tiene `aislar_xdg`, se usa una carpeta temporal para las rutas XDG.
    """
    overrides = overrides or {}
    conf = overrides.get(herramienta.nombre) or {}
    ruta = conf.get("path") or shutil.which(herramienta.binario)
    if not ruta:
        return Deteccion(False, None, None, "no encontrada en PATH")
    if herramienta.version_args is None:
        return Deteccion(True, None, ruta, None)
    try:
        if env is None and herramienta.aislar_xdg:
            with tempfile.TemporaryDirectory(prefix="mrrobotia_xdg_") as tmp:
                env = {**os.environ, "XDG_DATA_HOME": tmp, "XDG_CONFIG_HOME": tmp, "XDG_CACHE_HOME": tmp}
                return Deteccion(True, _consultar_version(herramienta, ruta, env), ruta, None)
        return Deteccion(True, _consultar_version(herramienta, ruta, env), ruta, None)
    except (OSError, subprocess.SubprocessError) as e:
        # Está en disco aunque falle la versión: disponible, pero sin versión.
        return Deteccion(True, None, ruta, type(e).__name__)


def _matar_arbol(proc):
    """Mata el proceso y todos sus descendientes (garak lanza procesos hijo con
    --parallel_attempts). En Windows, taskkill /T; en POSIX, el grupo de procesos."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                           capture_output=True, timeout=30)
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
        proc.wait(timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass


def _ejecutar_a_fichero(args, timeout, cwd, env, salida):
    """Ejecución larga: stdout y stderr van al fichero `salida` (no se acumulan en memoria), el
    proceso corre en su propio grupo y, si se agota `timeout` o se pulsa Ctrl-C, se mata todo el
    árbol de procesos. Ctrl-C no propaga la excepción: devuelve `error="interrumpido"` para que
    el llamador pueda dar un resultado parcial."""
    kw = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt"
          else {"start_new_session": True})
    try:
        with open(salida, "wb") as f:
            proc = subprocess.Popen(list(args), stdout=f, stderr=subprocess.STDOUT,
                                    stdin=subprocess.DEVNULL, cwd=cwd, env=env, **kw)
            fin = time.monotonic() + timeout
            try:
                while True:
                    # Tramos cortos: en Windows una espera larga no se interrumpe con Ctrl-C.
                    restante = fin - time.monotonic()
                    if restante <= 0:
                        _matar_arbol(proc)
                        return Resultado(None, "", "", True, "timeout")
                    try:
                        return Resultado(proc.wait(timeout=min(0.5, restante)), "", "", False, None)
                    except subprocess.TimeoutExpired:
                        continue
            except KeyboardInterrupt:
                _matar_arbol(proc)
                return Resultado(None, "", "", False, "interrumpido")
    except OSError as e:
        return Resultado(None, "", "", False, f"{type(e).__name__}: {str(e)[:120]}")


def ejecutar(args, *, timeout=600, cwd=None, env=None, entrada=None, salida=None):
    """Ejecuta un proceso externo de forma segura y captura su salida.

    `args` es una lista (orden + argumentos); NUNCA se usa `shell=True`. Captura
    stdout/stderr como texto UTF-8, sustituyendo lo que no decodifique. Marca
    `expiro=True` si se agota `timeout`, y nunca propaga la excepción: los errores de
    arranque (OSError) vuelven en `error`.

    Con `salida` (ruta de un fichero) es una ejecución larga: la salida (stdout y stderr
    juntos) se escribe en ese fichero en lugar de capturarse, `Resultado.stdout` queda vacío,
    y al agotarse `timeout` o con Ctrl-C se mata el árbol de procesos entero.
    """
    if salida is not None:
        return _ejecutar_a_fichero(args, timeout, cwd, env, salida)
    try:
        proc = subprocess.run(
            list(args), capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, cwd=cwd, env=env, input=entrada)
        return Resultado(proc.returncode, proc.stdout, proc.stderr, False, None)
    except subprocess.TimeoutExpired as e:
        return Resultado(None, e.stdout or "", e.stderr or "", True, "timeout")
    except OSError as e:
        return Resultado(None, "", "", False, f"{type(e).__name__}: {str(e)[:120]}")


def _version_menor(a, b):
    """¿Es la versión `a` estrictamente menor que `b`? Compara por tuplas de int.

    Rellena con ceros la más corta ("1.2" -> (1,2,0) frente a "1.2.5"). Si alguna
    no parsea a enteros separados por puntos, devuelve False: ante una versión
    rara no bloqueamos la ejecución (preferimos no emitir un falso "antigua").
    """
    try:
        ta = tuple(int(x) for x in str(a).split("."))
        tb = tuple(int(x) for x in str(b).split("."))
    except (ValueError, AttributeError):
        return False
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return ta < tb


class ModuloHerramienta(Modulo):
    """Base de un módulo que delega en una herramienta externa.

    Una subclase (p. ej. el futuro envoltorio de garak) solo tiene que:
      - fijar `nombre`, `titulo`, `herramienta = Herramienta(...)` y `activo`;
      - implementar `_auditar(objetivo, det)` llamando a
        `ejecutar([det.ruta, ...], timeout=self._timeout(objetivo))` y parseando
        `Resultado.stdout` a una lista de `Hallazgo`.

    `ejecutar()` resuelve el resto del patrón común: detección, hallazgo si la
    herramienta no está instalada, aviso de versión antigua y el hallazgo de
    trazabilidad (versión usada) que encabeza siempre la salida.
    """
    herramienta: Herramienta = None
    activo = False

    def _env_deteccion(self, objetivo):
        """Entorno con el que se consulta la versión de la herramienta, o None = el actual."""
        return None

    def ejecutar(self, objetivo):
        overrides = objetivo.get("tools", {}) or {}
        env = self._env_deteccion(objetivo)
        det = (detectar(self.herramienta, overrides, env=env) if env is not None
               else detectar(self.herramienta, overrides))
        if not det.disponible:
            # Orquestar, no reinventar: se informa, no se revienta.
            return [Hallazgo(
                self.nombre, f"{self.nombre}-NO-INSTALADA",
                f"{self.herramienta.nombre} no está instalada",
                Severidad.INFO, "informativo", det.error or "",
                f"Instálala para este análisis: {como_instalar(self.herramienta)}",
                self.herramienta.refs)]

        h = list(self._auditar(objetivo, det))
        # Aviso opcional de versión por debajo de la mínima recomendada.
        if (self.herramienta.min_version and det.version
                and _version_menor(det.version, self.herramienta.min_version)):
            h.insert(0, Hallazgo(
                self.nombre, f"{self.nombre}-VERSION-ANTIGUA",
                f"{self.herramienta.nombre} en una versión anterior a la recomendada",
                Severidad.MEDIA, "informativo",
                f"version={det.version} < {self.herramienta.min_version}",
                f"Actualiza {self.herramienta.nombre} a {self.herramienta.min_version} o superior.",
                self.herramienta.refs))
        # Primer hallazgo: trazabilidad (reproducibilidad para el TFG), sin secretos.
        h.insert(0, Hallazgo(
            self.nombre, f"{self.nombre}-VERSION",
            f"{self.herramienta.nombre} ejecutada",
            Severidad.INFO, "informativo",
            f"version={det.version or 'desconocida'}"))
        return h

    def _auditar(self, objetivo, det) -> list[Hallazgo]:
        """Lanza la herramienta y normaliza su salida a hallazgos. Lo implementa
        cada hito concreto (H3 Trivy, H4 garak, H5 promptfoo, H6 DeepEval…)."""
        raise NotImplementedError

    def _timeout(self, objetivo, defecto=600):
        """Timeout en segundos para esta herramienta: `objetivo["tools"]
        [nombre]['timeout']` si está declarado, si no `defecto`."""
        try:
            return objetivo["tools"][self.herramienta.nombre]["timeout"]
        except (KeyError, TypeError):
            return defecto
