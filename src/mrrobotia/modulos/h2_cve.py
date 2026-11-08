"""
H2-CVE — Versión de cada servidor identificado frente a los avisos de seguridad publicados.

Módulo PASIVO: no toca la red y trabaja con la versión que H2-ID dejó en `self.contexto`. Una
coincidencia por versión es un indicio, no una prueba de que el fallo sea explotable: por eso
sale como `potencial`. Una versión que queda por encima del último valor probado de un aviso
sin corrección publicada es indeterminada y sale como INFO, nunca como vulnerable.

Si se sabe que un componente no está en uso (el backend RPC sin `--rpc`, por ejemplo), sus
avisos no cuentan como coincidencias; si no se puede saber, se avisa de ello en la evidencia.

Marcos: OWASP LLM Top 10 2025 (LLM03), MITRE ATLAS (AML.T0010) y NIST AI 600-1 (2.12).
"""
from __future__ import annotations

from mrrobotia import cve
from mrrobotia.contexto import rotular
from mrrobotia.nucleo import Hallazgo, Modulo, Severidad
from mrrobotia.perfiles import perfil_de
from mrrobotia.perfiles.base import REFS_SUPPLY

MODULO = "H2-CVE"
_GRUPOS = (Severidad.CRITICA, Severidad.ALTA, Severidad.MEDIA, Severidad.BAJA)


def _info(id_, titulo, evidencia, recomendacion=""):
    return Hallazgo(MODULO, id_, titulo, Severidad.INFO, "informativo", evidencia, recomendacion, REFS_SUPPLY)


def _etiqueta(aviso):
    """Identificador del aviso y, si se conoce, su componente."""
    nombre = cve.componente(aviso)
    return f"{aviso['id']} [{nombre}]" if nombre else str(aviso["id"])


def _lista(avisos):
    return ", ".join(_etiqueta(a) for a in sorted(avisos, key=lambda a: str(a["id"])))


def _hallazgo_grupo(severidad, avisos, version, sin_confirmar, clave_version):
    """Un hallazgo con todos los avisos de la misma severidad."""
    evidencia = f"versión {version}: {len(avisos)} aviso(s): {_lista(avisos)}"
    if sin_confirmar:
        evidencia += "; sin confirmar si se usa: " + ", ".join(sorted(sin_confirmar))
    corregidos = [a["corregido_en"] for a in avisos
                  if a.get("corregido_en") and clave_version(a["corregido_en"]) is not None]
    correccion = max(corregidos, key=clave_version) if corregidos else None
    recomendacion = (f"Actualiza a {correccion} o posterior" if correccion
                     else "No consta corrección publicada: vigila los avisos")
    return Hallazgo(
        MODULO, f"H2-CVE-{severidad.name}", f"La versión del servidor coincide con avisos de severidad {severidad.name}",
        severidad, "potencial", evidencia,
        recomendacion + ". La coincidencia es por versión: confirma en cada aviso si tu compilación y tu configuración "
        "están afectadas; en paquetes de terceros, el número de versión puede no ser comparable (LLM03).", REFS_SUPPLY)


class H2Cve(Modulo):
    nombre = MODULO
    titulo = "Versión del servidor LLM frente a avisos de seguridad"
    activo = False
    etiqueta_escaneo = "cve"

    def ejecutar(self, objetivo):
        if self.contexto is None:
            return [self.hallazgo_sin_contexto()]
        hallazgos = []
        for servidor in self.contexto.servidores:
            try:
                parciales = self._cruzar(servidor)
            except Exception as e:          # invariante: un fallo nunca llega al llamador
                parciales = [_info("H2-CVE-ERROR", "Error al cruzar los avisos", type(e).__name__)]
            hallazgos.extend(rotular(parciales, servidor))
        return hallazgos or [_info("H2-CVE-SIN-DATOS", "Sin versiones que cruzar",
                                   "H2-ID no ha identificado ningún servidor")]

    @staticmethod
    def _cruzar(servidor):
        perfil = perfil_de(servidor)
        avisos = cve.cargar(perfil.fichero_cve) if perfil.fichero_cve else []
        if not avisos or perfil.clave_version is None:
            return [_info("H2-CVE-SIN-BASE", "Sin base de avisos para este servidor", f"tipo: {servidor.tipo}")]
        if not servidor.version:
            return [_info("H2-CVE-SIN-VERSION", "No se conoce la versión del servidor",
                          "sin versión no se pueden cruzar los avisos",
                          "Con --permitir-activos, MRRobotIA intenta leerla del propio servidor.")]
        if perfil.clave_version(servidor.version) is None:
            return [_info("H2-CVE-SIN-VERSION", "La versión del servidor no se puede comparar",
                          f"versión {servidor.version}",
                          "Una compilación sin datos de versión no se puede cruzar con los avisos.")]

        def en_uso(aviso):
            return perfil.componente_en_uso(aviso, servidor)

        resultado = cve.clasificar(servidor.version, avisos, perfil.clave_version, en_uso)
        hallazgos = []
        for severidad in _GRUPOS:
            grupo = [a for a in resultado.afectados if cve.severidad_de(a) == severidad]
            if grupo:
                sin_confirmar = {cve.componente(a) or a["id"] for a in grupo if en_uso(a) is None}
                hallazgos.append(_hallazgo_grupo(severidad, grupo, servidor.version, sin_confirmar, perfil.clave_version))
        if resultado.indeterminados:
            hallazgos.append(_info(
                "H2-CVE-INDETERMINADOS", "Avisos sin corrección publicada posteriores a lo probado",
                f"versión {servidor.version}: {_lista(resultado.indeterminados)}",
                "Esta versión queda por encima de lo que probó quien informó y no consta corrección: no se puede "
                "afirmar que esté afectada ni que no. Revisa cada aviso si usas ese componente."))
        if resultado.no_aplican:
            hallazgos.append(_info("H2-CVE-NO-APLICA", "Avisos de componentes que este servidor no usa",
                                   f"versión {servidor.version}: {_lista(resultado.no_aplican)}"))
        return hallazgos or [_info("H2-CVE-SIN-COINCIDENCIAS", "Sin coincidencias con los avisos conocidos",
                                   f"versión {servidor.version}: {len(avisos)} avisos revisados",
                                   "La base de avisos puede no estar al día: esto no garantiza que no haya fallos.")]
