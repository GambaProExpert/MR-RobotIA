"""
M2 — Integridad de artefactos (.gguf y bases vectoriales ChromaDB).

Módulo PASIVO y de SOLO LECTURA: calcula el SHA-256 de cada artefacto declarado y
lo compara con un manifiesto de confianza. Detecta artefactos ausentes, alterados,
sin hash de referencia y manifiestos sin firmar. Nunca modifica un artefacto.

Atacante del modelo de amenazas: A4 (cadena de suministro) y A3 (acceso a disco).
"""
import hashlib
import json
from pathlib import Path

from mrrobotia.nucleo import Modulo, Hallazgo, Severidad

REFS = {"owasp": "LLM03", "atlas": "AML.T0010", "nist": "2.12"}


def sha256_fichero(ruta, bloque=1 << 20):
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for trozo in iter(lambda: f.read(bloque), b""):
            h.update(trozo)
    return h.hexdigest()


class M2Integridad(Modulo):
    nombre = "M2"
    titulo = "Integridad de artefactos (.gguf, ChromaDB)"
    activo = False
    etiqueta_escaneo = "integridad"

    def ejecutar(self, objetivo):
        hallazgos = []
        manifiesto = {}
        ruta_manif = objetivo.get("manifiesto")
        if ruta_manif:
            if Path(ruta_manif).exists():
                manifiesto = json.loads(Path(ruta_manif).read_text(encoding="utf-8"))
                if not objetivo.get("manifiesto_firmado"):
                    hallazgos.append(Hallazgo(
                        "M2", "M2-MANIF-SIN-FIRMA", "El manifiesto de integridad no está firmado",
                        Severidad.MEDIA, "confirmado", str(ruta_manif),
                        "Firma el manifiesto (p. ej. OpenSSF model-signing o minisign). Sin firma, "
                        "un atacante con acceso a disco puede reescribir a la vez el artefacto y su hash.",
                        {"owasp": "LLM03", "nist": "2.12"}))
            else:
                hallazgos.append(Hallazgo(
                    "M2", "M2-MANIF-FALTA", "No se encuentra el manifiesto declarado",
                    Severidad.ALTA, "confirmado", str(ruta_manif),
                    "Genera un manifiesto de integridad de los artefactos y protégelo.", REFS))

        artefactos = objetivo.get("artefactos", [])
        if not artefactos:
            hallazgos.append(Hallazgo(
                "M2", "M2-SIN-ARTEFACTOS", "No hay artefactos declarados para verificar",
                Severidad.INFO, "informativo", "",
                "Añade los .gguf y las bases vectoriales al fichero de objetivo."))

        for art in artefactos:
            ruta = Path(art["ruta"])
            nombre = ruta.name
            esperado = art.get("sha256") or (manifiesto.get(nombre) or {}).get("sha256")
            if not ruta.exists():
                hallazgos.append(Hallazgo(
                    "M2", f"M2-FALTA-{nombre}", f"Artefacto ausente: {nombre}",
                    Severidad.ALTA, "confirmado", str(ruta),
                    "Restaura el artefacto desde una copia de confianza.", REFS))
                continue
            real = sha256_fichero(ruta)
            if not esperado:
                hallazgos.append(Hallazgo(
                    "M2", f"M2-SINREF-{nombre}", f"Sin hash de referencia para {nombre}",
                    Severidad.MEDIA, "confirmado", f"sha256 actual: {real}",
                    "Registra este hash en el manifiesto firmado para poder detectar alteraciones.", REFS))
            elif real.lower() != esperado.lower():
                hallazgos.append(Hallazgo(
                    "M2", f"M2-ALTERADO-{nombre}", f"El artefacto NO coincide con el manifiesto: {nombre}",
                    Severidad.CRITICA, "confirmado", f"esperado {esperado[:16]}…, real {real[:16]}…",
                    "No cargues el artefacto; investiga la alteración (posible compromiso de cadena de suministro).",
                    {"owasp": "LLM03", "atlas": "AML.T0018.000", "nist": "2.12"}))
            else:
                hallazgos.append(Hallazgo(
                    "M2", f"M2-OK-{nombre}", f"Integridad verificada: {nombre}",
                    Severidad.INFO, "informativo", f"sha256 {real[:16]}…"))
        return hallazgos
