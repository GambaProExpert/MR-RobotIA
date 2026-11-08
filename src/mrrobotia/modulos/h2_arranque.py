"""
H2-ARRANQUE — Cómo se arrancó cada servidor identificado: opciones y entorno.

Módulo PASIVO: no toca la red. Trabaja con lo que H2-ID dejó en `self.contexto`, que por
construcción solo guarda opciones de una lista blanca y saneadas, con los secretos convertidos
en `True`; las severidades, según el perfil de cada servidor. Además, busca en el entorno del
PROPIO SERVIDOR, nunca en el del auditor, claves de proveedores externos: de nuevo, solo presencia.

Atacantes del modelo de amenazas: A5 (exposición) y A3 (procesos locales). Marcos: OWASP LLM
Top 10 2025 (LLM10, LLM02, LLM03), MITRE ATLAS y NIST AI 600-1.
"""
from __future__ import annotations

from mrrobotia import procesos, red
from mrrobotia.contexto import rotular
from mrrobotia.nucleo import Hallazgo, Modulo, Severidad
from mrrobotia.perfiles import perfil_de
from mrrobotia.perfiles.base import MODULO_ARRANQUE as MODULO
from mrrobotia.perfiles.base import REFS_SECRETOS

# Nombres (nunca valores) de claves de proveedores que no deberían estar en un servidor auto alojado.
CLAVES_PROVEEDOR = {nombre: True for nombre in (
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID", "GOOGLE_API_KEY", "GEMINI_API_KEY", "COHERE_API_KEY", "AZURE_OPENAI_API_KEY",
    "GROQ_API_KEY", "MISTRAL_API_KEY",
)}


def _evaluar_env(nombres):
    """Claves de proveedores en el entorno del servidor. La evidencia son nombres."""
    if nombres:
        return Hallazgo(
            MODULO, "H2-ENV", "Hay claves de API de proveedores en el entorno del servidor", Severidad.MEDIA,
            "confirmado", "variables presentes: " + ", ".join(sorted(nombres)),
            "Un servidor LLM auto alojado no debería necesitar claves de proveedores externos en su entorno: si el "
            "proceso se ve comprometido, se exponen. Retíralas o usa un gestor de secretos.", REFS_SECRETOS)
    return Hallazgo(MODULO, "H2-ENV", "No hay claves de API de proveedores en el entorno del servidor", Severidad.INFO,
                    "informativo", "ninguna de las variables vigiladas está presente", "", REFS_SECRETOS)


def _hallazgo_entorno(servidor):
    """Entorno del proceso del servidor. Si no se puede leer, se dice y no se afirma nada."""
    if servidor.pid is None:
        return Hallazgo(MODULO, "H2-ENV", "Entorno del servidor sin comprobar", Severidad.INFO, "informativo",
                        "no hay un proceso local asociado a este servidor", "", REFS_SECRETOS)
    presentes = procesos.leer_entorno(servidor.pid, CLAVES_PROVEEDOR)
    if not presentes and not procesos.entorno_legible(servidor.pid):
        return Hallazgo(MODULO, "H2-ENV", "Entorno del servidor sin comprobar", Severidad.INFO, "informativo",
                        "el entorno del proceso no es legible (en Windows no se expone a otros procesos; en Linux, "
                        "solo al propietario o a root)",
                        "Comprueba a mano que el proceso no tenga claves de proveedores externos.", REFS_SECRETOS)
    return _evaluar_env(presentes)


class H2Arranque(Modulo):
    nombre = MODULO
    titulo = "Opciones de arranque y entorno del servidor LLM"
    activo = False
    etiqueta_escaneo = "arranque"

    def ejecutar(self, objetivo):
        if self.contexto is None:
            return [self.hallazgo_sin_contexto()]
        hallazgos = []
        for servidor in self.contexto.servidores:
            parciales = []
            try:
                self._evaluar(servidor, parciales)
            except Exception as e:          # invariante: un fallo nunca llega al llamador
                parciales.append(Hallazgo(MODULO, "H2-ARRANQUE-ERROR", "Error al evaluar el arranque", Severidad.INFO,
                                          "informativo", type(e).__name__, "", {}))
            hallazgos.extend(rotular(parciales, servidor))
        if not hallazgos:
            hallazgos.append(Hallazgo(MODULO, "H2-ARRANQUE-SIN-DATOS", "Sin datos de arranque", Severidad.INFO,
                                      "informativo", "H2-ID no ha identificado ningún servidor", "", {}))
        return hallazgos

    @staticmethod
    def _evaluar(servidor, h):
        h.append(_hallazgo_entorno(servidor))
        if not servidor.opciones and not servidor.entorno:
            h.append(Hallazgo(MODULO, "H2-ARRANQUE-SIN-OPCIONES", "Opciones de arranque no disponibles", Severidad.INFO,
                              "informativo", "no se conoce su línea de órdenes (proceso remoto o no legible)",
                              "Revisa a mano con qué opciones se arrancó.", {}))
            return
        h.extend(perfil_de(servidor).evaluar_arranque(servidor, red.es_no_loopback(servidor.enlace)))
