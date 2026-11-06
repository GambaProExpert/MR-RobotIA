"""
Núcleo orquestador de herramientas externas de seguridad para MRRobot.

MRRobot no reimplementa cada comprobación: ejecuta herramientas ya consolidadas
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

import re
import shutil
import subprocess
from dataclasses import dataclass, field

from mrrobot.nucleo import Modulo, Hallazgo, Severidad

# Primer número de versión tipo "x.y" o "x.y.z" que aparezca en la salida de --version.
_RE_VERSION = re.compile(r"\d+\.\d+(?:\.\d+)?")


@dataclass(frozen=True)
class Herramienta:
    """Descripción estática de una herramienta externa de línea de órdenes.

    - `nombre`: identificador corto usado en los IDs de hallazgo y en los overrides
      del objetivo (p. ej. "garak").
    - `binario`: nombre del ejecutable que se buscará en el PATH (p. ej. "garak").
    - `version_args`: argumentos para preguntar la versión (p. ej. ("--version",)).
    - `instalar_con`: orden sugerida de instalación offline para el hallazgo.
    - `min_version`: versión mínima recomendada ("x.y[.z]") o None.
    - `refs`: marcos asociados (OWASP/ATLAS/NIST) para los hallazgos del módulo.
    """
    nombre: str
    binario: str
    version_args: tuple = ("--version",)
    instalar_con: str = ""
    min_version: str | None = None
    refs: dict = field(default_factory=dict)


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


def _extraer_version(texto):
    """Primer 'x.y' o 'x.y.z' que aparezca en el texto; None si no hay ninguno."""
    m = _RE_VERSION.search(texto or "")
    return m.group(0) if m else None


def detectar(herramienta, overrides=None):
    """Busca la herramienta y, si está, consulta su versión.

    La ruta efectiva es `overrides[nombre]["ruta"]` si existe; si no, lo que
    devuelva `shutil.which(binario)`. Nunca lanza: si el binario está en disco
    pero falla la consulta de versión, sigue considerándose DISPONIBLE (con
    `version=None` y el tipo de error), porque existe y podrá ejecutarse.
    """
    overrides = overrides or {}
    conf = overrides.get(herramienta.nombre) or {}
    ruta = conf.get("ruta") or shutil.which(herramienta.binario)
    if not ruta:
        return Deteccion(False, None, None, "no encontrada en PATH")
    try:
        proc = subprocess.run(
            [ruta, *herramienta.version_args],
            capture_output=True, text=True, timeout=10)
        version = _extraer_version((proc.stdout or "") + "\n" + (proc.stderr or ""))
        return Deteccion(True, version, ruta, None)
    except (OSError, subprocess.SubprocessError) as e:
        # Está en disco aunque falle la versión: disponible, pero sin versión.
        return Deteccion(True, None, ruta, type(e).__name__)


def ejecutar(args, *, timeout=600, cwd=None, env=None, entrada=None):
    """Ejecuta un proceso externo de forma segura y captura su salida.

    `args` es una lista (orden + argumentos); NUNCA se usa `shell=True`. Captura
    stdout/stderr como texto. Marca `expiro=True` si se agota `timeout`, y nunca
    propaga la excepción: los errores de arranque (OSError) vuelven en `error`.
    """
    try:
        proc = subprocess.run(
            list(args), capture_output=True, text=True,
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

    def ejecutar(self, objetivo):
        overrides = objetivo.get("herramientas", {}) or {}
        det = detectar(self.herramienta, overrides)
        if not det.disponible:
            # Orquestar, no reinventar: se informa, no se revienta.
            return [Hallazgo(
                self.nombre, f"{self.nombre}-NO-INSTALADA",
                f"{self.herramienta.nombre} no está instalada",
                Severidad.INFO, "informativo", det.error or "",
                f"Instálala para este análisis: {self.herramienta.instalar_con}",
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
        """Timeout en segundos para esta herramienta: `objetivo['herramientas']
        [nombre]['timeout']` si está declarado, si no `defecto`."""
        try:
            return objetivo["herramientas"][self.herramienta.nombre]["timeout"]
        except (KeyError, TypeError):
            return defecto
