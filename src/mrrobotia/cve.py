"""
Avisos de seguridad publicados y su comparación con la versión de un servidor.

Una coincidencia por versión es un indicio, no una prueba: H2-CVE la presenta como
`potencial`. Cada producto numera a su manera, así que la comparación recibe de su perfil
`clave_version`, la función que convierte una versión en algo comparable (o en None si no
se puede interpretar). Basta con añadir otra de esas funciones para otro producto.

`afecta` es una lista de comparadores separados por comas (`">=b3978,<=b9058"`) y, para los
productos cuyos avisos cubren varios tramos, alternativas separadas por ` || `.
"""
from __future__ import annotations

import json
import operator
import re
from dataclasses import dataclass, field
from pathlib import Path

from mrrobotia.nucleo import Severidad

DIR_DATOS = Path(__file__).resolve().parent / "datos"
AFECTADA, NO_AFECTADA, INDETERMINADA = "afectada", "no_afectada", "indeterminada"

_OPERADORES = {"<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge,
               "=": operator.eq, "==": operator.eq}
_COTAS_SUPERIORES = {"<", "<="}
_RE_BUILD = re.compile(r"b(\d+)(?:-[0-9a-f]+)?")
_RE_PEP440 = re.compile(r"v?(\d+(?:\.\d+)*)(?:(a|b|rc)(\d+))?(?:\.post(\d+))?(?:\.dev(\d+))?"
                        r"(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?", re.IGNORECASE)
_ORDEN_PREVIA = {"a": 0, "b": 1, "rc": 2}
_SIN_PREVIA = 3             # una versión final va detrás de sus candidatas
_SOLO_DEV = -1              # y `1.0.dev1`, por delante de `1.0a1`
_RE_COMPARADOR = re.compile(r"(<=|>=|==|<|>|=)?\s*(\S+)")
_RE_COMPONENTE = re.compile(r"\[([\w-]+)\]")


def cargar(fichero):
    """Avisos de `datos/<fichero>`; [] si falta o no tiene la forma esperada. Nunca lanza."""
    try:
        datos = json.loads((DIR_DATOS / fichero).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return []
    if not isinstance(datos, list):
        return []
    return [a for a in datos if isinstance(a, dict) and a.get("id")]


def clave_build(version):
    """Número de build de llama.cpp (`b11583-988015788` o `b11583`, según de dónde venga), o
    None si no se puede interpretar. `b0-unknown` es una compilación sin datos de git."""
    m = _RE_BUILD.fullmatch(version) if isinstance(version, str) else None
    numero = int(m.group(1)) if m else 0
    return numero or None


def clave_pep440(version):
    """Subconjunto de PEP 440 que usan vLLM y sus avisos: `0.33.0`, `0.33.0rc3`, `0.5.0.post1`,
    `0.33.0.dev1` y `0.33.0+cpu`. Devuelve algo comparable o None; `dev` a secas no lo es.

    El orden es el de PEP 440: `1.0.dev1 < 1.0a1 < 1.0rc1.dev2 < 1.0rc1 < 1.0 < 1.0.post1`. La parte
    local (`+cpu`) no cuenta: una compilación para CPU es la misma versión a efectos de los avisos.
    """
    m = _RE_PEP440.fullmatch(version.strip()) if isinstance(version, str) else None
    if m is None:
        return None
    partes = [int(p) for p in m.group(1).split(".")]
    while partes and partes[-1] == 0:   # 0.33 y 0.33.0 son la misma versión
        partes.pop()
    previa, post, dev = m.group(2), m.group(4), m.group(5)
    if previa:
        fase = (_ORDEN_PREVIA[previa.lower()], int(m.group(3)))
    else:
        fase = (_SOLO_DEV if dev is not None and post is None else _SIN_PREVIA, 0)
    return (tuple(partes), fase, -1 if post is None else int(post),
            float("inf") if dev is None else int(dev))


def _comparadores(expresion, clave_version):
    """[(operador, límite)] de una expresión con comas, o None si alguna parte no se entiende."""
    lista = []
    for parte in str(expresion).split(","):
        m = _RE_COMPARADOR.fullmatch(parte.strip())
        limite = clave_version(m.group(2)) if m else None
        if limite is None:
            return None
        lista.append((m.group(1) or "=", limite))
    return lista


def estado_aviso(version, aviso, clave_version):
    """Si la versión está afectada por el aviso.

    1. Cumple todos los comparadores de una alternativa: afectada.
    2. Queda fuera y hay corrección publicada, o queda antes del inicio del rango: no afectada.
    3. Queda por encima del límite y no hay corrección: indeterminada. Ese límite es la última
       versión que probó quien informó, no la última vulnerable: nunca debe salir como vulnerable.
    """
    clave = clave_version(version)
    alternativas = [_comparadores(a, clave_version) for a in str(aviso.get("afecta") or "").split("||")]
    if clave is None or not all(alternativas):
        return INDETERMINADA
    por_encima = False
    for comparadores in alternativas:
        incumplidos = {op for op, limite in comparadores if not _OPERADORES[op](clave, limite)}
        if not incumplidos:
            return AFECTADA
        por_encima = por_encima or incumplidos <= _COTAS_SUPERIORES
    return INDETERMINADA if por_encima and not aviso.get("corregido_en") else NO_AFECTADA


def componente(aviso):
    """Componente que afecta el aviso (`[rpc]` al inicio del resumen), o None."""
    m = _RE_COMPONENTE.match(str(aviso.get("resumen") or ""))
    return m.group(1) if m else None


def severidad_de(aviso):
    """Severidad declarada en el aviso o, si no la hay, la que corresponde a su CVSS. Sin
    ninguna de las dos no se presenta como menor: MEDIA."""
    nombre = str(aviso.get("severidad") or "").upper()
    if nombre in Severidad.__members__:
        return Severidad[nombre]
    cvss = aviso.get("cvss")
    if not isinstance(cvss, (int, float)):
        return Severidad.MEDIA
    for tope, severidad in ((9.0, Severidad.CRITICA), (7.0, Severidad.ALTA), (4.0, Severidad.MEDIA)):
        if cvss >= tope:
            return severidad
    return Severidad.BAJA


@dataclass
class Clasificacion:
    afectados: list = field(default_factory=list)
    indeterminados: list = field(default_factory=list)
    no_aplican: list = field(default_factory=list)      # el componente no está en uso


def clasificar(version, avisos, clave_version, en_uso=lambda aviso: None):
    """Reparte los avisos que tocan a esta versión. `en_uso(aviso)` devuelve False si el
    servidor no usa el componente afectado; lo descartado queda en `no_aplican`."""
    resultado = Clasificacion()
    for aviso in avisos:
        estado = estado_aviso(version, aviso, clave_version)
        if estado == NO_AFECTADA:
            continue
        if en_uso(aviso) is False:
            resultado.no_aplican.append(aviso)
        elif estado == AFECTADA:
            resultado.afectados.append(aviso)
        else:
            resultado.indeterminados.append(aviso)
    return resultado
