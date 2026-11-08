"""
Perfil genérico: servidor compatible con la API de OpenAI del que no se sabe nada más.

Es el último recurso: se aplica cuando ni los perfiles específicos ni Julius reconocen el
servicio. Una coincidencia aquí solo dice que hay una API con esa forma, de ahí la confianza baja.
"""
from __future__ import annotations

from mrrobotia.perfiles.base import MAX_MODELOS, Identificacion, Perfil, nombre_modelo


class Generico(Perfil):
    id = "generico"
    nombre = "compatible con OpenAI"

    def identificar_http(self, cliente) -> Identificacion | None:
        respuesta = cliente.get("/v1/models")
        datos = respuesta.json()
        if not isinstance(datos, dict):
            return None
        if respuesta.estado == 200 and "object" in datos and isinstance(datos.get("data"), list):
            ids = [d.get("id") for d in datos["data"][:MAX_MODELOS] if isinstance(d, dict)]
            nombres = [n for n in (nombre_modelo(i) for i in ids) if n]
            return Identificacion(self.id, "baja", None, "abierta", ["/v1/models con forma de OpenAI"], nombres)
        if respuesta.estado in (401, 403) and "error" in datos:
            return Identificacion(self.id, "baja", None, "activa", [f"/v1/models responde {respuesta.estado} con error JSON"])
        return None
