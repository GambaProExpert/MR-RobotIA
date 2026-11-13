"""
H2-ARRANQUE — Cómo se arrancó cada servidor identificado: opciones y entorno.

Módulo PASIVO: no toca la red. Trabaja con lo que H2-ID dejó en `self.contexto`, que por
construcción solo guarda opciones de una lista blanca y saneadas, con los secretos convertidos
en `True`; las severidades, según el perfil de cada servidor. Además, busca en el entorno del
PROPIO SERVIDOR, nunca en el del auditor, claves de proveedores externos: de nuevo, solo presencia.

H2 corre antes (el orden de `cli.MODULOS` lo garantiza) y lo observado en el servidor real manda
sobre lo que dice su línea de órdenes: una fila cuyo asunto H2 ya ha podido concluir se descarta,
para que una causa dé un único hallazgo. Con `--scan startup` solo, H2 no corre y salen todas.

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


# Fila de arranque -> hallazgo de H2 que trata el mismo asunto. Dos hallazgos para una causa inflarían
# el resumen del informe. Lo que H2 no ha podido concluir no cuenta: esa fila sigue siendo la única pista.
FILA_A_OBSERVADO = {
    "H2-ARRANQUE-HOST": "H2-BIND",
    "H2-ARRANQUE-SIN-CLAVE": "H2-AUTH",
    "H2-ARRANQUE-TLS": "H2-TLS",
    "H2-ARRANQUE-CORS": "H2-CORS",
    "H2-ARRANQUE-WEBUI": "H2-WEBUI",
    "H2-ARRANQUE-SLOTS": "H2-SLOTS",
    "H2-ARRANQUE-METRICS": "H2-METRICS",
    "H2-ARRANQUE-PROPS": "H2-PROPS-ESCRITURA",
    "H2-ARRANQUE-ROUTER": "H2-ROUTER",
    "H2-ARRANQUE-MCP-PROXY": "H2-CORS-PROXY",
    "H2-ARRANQUE-SLOT-SAVE": "H2-SLOT-SAVE",
    "H2-ARRANQUE-TOOLS": "H2-TOOLS",
    # vLLM
    "H2-ARRANQUE-DESARROLLO": "H2-DESARROLLO",
    "H2-ARRANQUE-OPENAPI": "H2-OPENAPI",
    "H2-ARRANQUE-LOAD": "H2-LOAD",
    "H2-ARRANQUE-TOKENIZER-INFO": "H2-TOKENIZER-INFO",
    "H2-ARRANQUE-TOKENS-ONLY": "H2-CONTROL-SIN-CLAVE",
    "H2-ARRANQUE-PROFILER": "H2-CONTROL-SIN-CLAVE",
    "H2-ARRANQUE-FAULT-TOLERANCE": "H2-CONTROL-SIN-CLAVE",
}


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
        return Hallazgo(MODULO, "H2-ENV", "Entorno del servidor sin comprobar", Severidad.INFO, "sin_concluir",
                        "el entorno del proceso no es legible (en Windows no se expone a otros procesos; en Linux, "
                        "solo al propietario o a root)",
                        "Comprueba a mano que el proceso no tenga claves de proveedores externos.", REFS_SECRETOS)
    return _evaluar_env(presentes)


class H2Arranque(Modulo):
    nombre = MODULO
    titulo = "Opciones de arranque y entorno del servidor LLM"
    activo = False
    etiqueta_escaneo = "startup"
    descripcion = "Opciones de arranque y entorno del proceso del servidor (clave en la línea de órdenes, CORS, TLS...)"
    tipo = "pasivo"

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
                              "sin_concluir", "no se conoce su línea de órdenes (proceso remoto o no legible)",
                              "Revisa a mano con qué opciones se arrancó.", {}))
            return
        filas = perfil_de(servidor).evaluar_arranque(servidor, red.es_no_loopback(servidor.enlace))
        h.extend(f for f in filas if FILA_A_OBSERVADO.get(f.id) not in servidor.observado)
