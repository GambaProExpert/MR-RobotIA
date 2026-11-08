"""
Contexto de la auditoría: qué se ha identificado antes de auditar.

Lo produce H2-ID, que corre siempre y primero, y lo reciben los demás módulos para adaptar
sus pruebas. Va al informe: por eso, por construcción, no contiene líneas de órdenes, claves,
valores de variables secretas ni rutas absolutas de modelos.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

_RANGO_CONFIANZA = {"alta": 2, "media": 1, "baja": 0}


def texto_enlace(enlace):
    """Texto legible de `ServidorDetectado.enlace`."""
    if isinstance(enlace, tuple):
        return str(enlace[1])
    return enlace or "desconocido"


def texto_direccion(servidor):
    """`host:puerto` de un servidor, o que el puerto no se conoce."""
    if servidor.puerto is None:
        return f"{servidor.host} (puerto desconocido)"
    return f"{servidor.host}:{servidor.puerto}"


def rotular(hallazgos, servidor):
    """Antepone a la evidencia de cada hallazgo de qué servidor habla: en un mismo host
    puede haber varios y sus hallazgos comparten identificador."""
    for hallazgo in hallazgos:
        hallazgo.evidencia = f"{servidor.tipo} en {texto_direccion(servidor)}: {hallazgo.evidencia}"
    return hallazgos


@dataclass
class ServidorDetectado:
    tipo: str                 # "llama.cpp" | "vllm" | "generico" | "otro:<servicio>"
    host: str
    puerto: int | None
    esquema: str = "http"
    prefijo: str = ""         # --api-prefix / --root-path o el del endpoint
    version: str | None = None
    confianza: str = "baja"   # "alta" | "media" | "baja"
    fuentes: list[str] = field(default_factory=list)  # "proceso","http","julius","declarado","forzado"
    pid: int | None = None
    enlace: object = None     # "loopback" | "todas" | ("otra", ip) | None
    opciones: dict = field(default_factory=dict)      # saneadas; secreto -> True
    entorno: dict = field(default_factory=dict)       # nombre -> valor no secreto, o True si secreto
    autenticacion: str | None = None  # "activa" | "abierta" | "indeterminada"
    modelos: list[str] = field(default_factory=list)  # nombre de fichero o alias, nunca ruta absoluta
    senales: list[str] = field(default_factory=list)  # evidencia corta y sin secretos

    @property
    def url(self):
        """URL base con la que preguntarle, incluido el prefijo. Exige que tenga puerto."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.esquema}://{host}:{self.puerto}{self.prefijo}"


@dataclass
class Contexto:
    so: str                   # "windows" | "linux" | "macos" | otro
    wsl: bool = False
    servidores: list[ServidorDetectado] = field(default_factory=list)

    def principal(self):
        """El servidor de mayor confianza (a igualdad, el primero), o None."""
        if not self.servidores:
            return None
        return max(self.servidores, key=lambda s: _RANGO_CONFIANZA.get(s.confianza, 0))

    def dict(self):
        """Versión serializable para el informe."""
        return asdict(self)
