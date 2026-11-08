"""
H3 — Vulnerabilidades, secretos y malas configuraciones del host (Trivy).

Módulo PASIVO: Trivy (`trivy fs`) solo LEE el disco local del despliegue, no
interactúa con el servicio, así que no está condicionado a `--permitir-activos`.
MRRobot no reimplementa el escaneo de CVEs: orquesta Trivy de forma LOCAL y
OFFLINE y normaliza su salida JSON a los `Hallazgo` del informe único.

Tres categorías de hallazgo, con su encaje en los marcos del TFG:
- Vulnerabilidades (CVE) de paquetes del sistema y lenguajes → cadena de
  suministro (OWASP LLM03, ATLAS AML.T0010).
- Malas configuraciones (Dockerfile, IaC, Kubernetes…) → misma familia.
- Secretos filtrados en el código/configuración → OWASP LLM02, ATLAS AML.T0025.

INVARIANTE DE PRIVACIDAD (crítico): para los secretos SOLO se registra el
identificador de la regla y `fichero:línea`. NUNCA se vuelca el valor del secreto
(los campos `Match`/`Code` de Trivy), porque el propio informe de auditoría no
debe convertirse en una filtración.

Atacante del modelo de amenazas: A4 (cadena de suministro) y A3 (acceso a disco).
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from mrrobot import herramientas
from mrrobot.herramientas import Herramienta, ModuloHerramienta
from mrrobot.nucleo import Hallazgo, Severidad

# Vulnerabilidades y malas configuraciones: cadena de suministro / integridad.
REFS_SUPPLY = {"owasp": "LLM03", "atlas": "AML.T0010", "nist": "2.12"}
# Secretos expuestos: fuga de información sensible.
REFS_SECRETOS = {"owasp": "LLM02", "atlas": "AML.T0025", "nist": "2.9"}

# Traducción de la severidad de Trivy a la escala interna de MRRobot.
MAPA_SEV = {
    "CRITICAL": Severidad.CRITICA,
    "HIGH": Severidad.ALTA,
    "MEDIUM": Severidad.MEDIA,
    "LOW": Severidad.BAJA,
    "UNKNOWN": Severidad.INFO,
}

# Tope de hallazgos mostrados por categoría; el resto se resume en un INFO.
MAX_POR_CATEGORIA = 25


def _sev(s):
    """Severidad de Trivy → `Severidad`; tolerante (default INFO ante lo desconocido)."""
    return MAPA_SEV.get(str(s or "").upper(), Severidad.INFO)


def _recorta(texto, n=110):
    """Recorta a `n` caracteres añadiendo un '…' si sobra; nunca None."""
    texto = (texto or "").strip()
    return texto if len(texto) <= n else texto[: n - 1] + "…"


def _conteo_sev(lista):
    """Recuento legible de severidades de una lista de hallazgos (de más a menos grave)."""
    c = Counter(h.severidad.name for h in lista)
    return ", ".join(f"{c[s]} {s}" for s in ("CRITICA", "ALTA", "MEDIA", "BAJA", "INFO") if c[s])


def _hallazgos_desde_trivy(obj, antiguedad=None):
    """Convierte el JSON de `trivy fs` en una lista de `Hallazgo`. Función PURA:
    NO toca disco ni procesos, por lo que es directamente testeable.

    `obj` es el diccionario ya parseado (`json.loads` de la salida de Trivy).
    `antiguedad` queda reservado para una futura señal de frescura de la base de
    datos; hoy el aviso de escaneo offline lo antepone `_auditar` como contexto.

    PRIVACIDAD: de los secretos solo se usan `RuleID`, `Target` y `StartLine`.
    Los campos `Match`/`Code` (que contienen el valor del secreto) NO se leen.
    """
    vulns, miscfgs, secrets = [], [], []

    for result in (obj.get("Results") or []):
        target = result.get("Target")
        if not target:
            continue

        for v in (result.get("Vulnerabilities") or []):
            vid = v.get("VulnerabilityID") or "?"
            fix = v.get("FixedVersion") or "—"
            evidencia = f"{v.get('PkgName')} {v.get('InstalledVersion')} ({vid}); fix {fix}"
            titulo = _recorta(v.get("Title") or f"Vulnerabilidad {vid}")
            vulns.append(Hallazgo(
                "H3-HOST", f"H3-HOST-CVE-{vid}", titulo,
                _sev(v.get("Severity")), "confirmado", evidencia,
                "actualiza el paquete a la versión con el parche", REFS_SUPPLY))

        for m in (result.get("Misconfigurations") or []):
            mid = m.get("ID") or m.get("AVDID") or "?"
            titulo_m = m.get("Title") or mid
            evidencia = _recorta(f"{target}: {titulo_m}", 200)
            recomendacion = _recorta(m.get("Resolution") or "corrige la configuración insegura.", 200)
            miscfgs.append(Hallazgo(
                "H3-HOST", f"H3-HOST-MISCONFIG-{mid}", _recorta(f"Configuración insegura: {titulo_m}"),
                _sev(m.get("Severity")), "confirmado", evidencia,
                recomendacion, REFS_SUPPLY))

        for s in (result.get("Secrets") or []):
            # SOLO regla + fichero:línea. NUNCA s["Match"] / s["Code"] (el valor).
            rule = s.get("RuleID") or "?"
            linea = s.get("StartLine", "?")
            evidencia = f"{rule} en {target}:{linea}"
            secrets.append(Hallazgo(
                "H3-HOST", f"H3-HOST-SECRET-{rule}", f"Posible secreto expuesto ({rule})",
                _sev(s.get("Severity")), "confirmado", evidencia,
                "retira el secreto del repositorio y rótalo; usa un gestor de secretos",
                REFS_SECRETOS))

    categorias = [
        ("vulnerabilidades", vulns),
        ("configuración", miscfgs),
        ("secretos", secrets),
    ]

    if not (vulns or miscfgs or secrets):
        return [Hallazgo(
            "H3-HOST", "H3-HOST-LIMPIO",
            "Trivy no encontró vulnerabilidades, secretos ni configuraciones inseguras por encima del umbral",
            Severidad.INFO, "informativo", "", "", REFS_SUPPLY)]

    salida, truncado = [], False
    for _, lista in categorias:
        ordenada = sorted(lista, key=lambda h: -int(h.severidad))
        if len(ordenada) > MAX_POR_CATEGORIA:
            truncado = True
        salida.extend(ordenada[:MAX_POR_CATEGORIA])

    if truncado:
        partes = [f"{et}: {len(lista)} ({_conteo_sev(lista)})"
                  for et, lista in categorias if lista]
        salida.insert(0, Hallazgo(
            "H3-HOST", "H3-HOST-RESUMEN",
            "Se recortó la lista de hallazgos de Trivy",
            Severidad.INFO, "informativo", "; ".join(partes),
            f"Se muestran como máximo {MAX_POR_CATEGORIA} hallazgos por categoría; "
            "consulta el informe completo de Trivy para verlos todos.", REFS_SUPPLY))

    return salida


class H3Host(ModuloHerramienta):
    """Escáner de host con Trivy: CVEs, malas configuraciones y secretos (pasivo)."""
    nombre = "H3-HOST"
    titulo = "Vulnerabilidades, secretos y configuración del host (Trivy)"
    activo = False               # Trivy solo lee disco local: PASIVO, no gated.
    etiqueta_escaneo = "vulns"

    herramienta = Herramienta(
        "trivy", "trivy",
        version_args=("--version",),
        instalar_con=(
            "https://trivy.dev/latest/getting-started/installation/ "
            "(winget install AquaSecurity.Trivy | brew install trivy | apt install trivy)"),
        refs=REFS_SUPPLY)

    def _auditar(self, objetivo, det) -> list[Hallazgo]:
        cfg = objetivo.get("host_trivy", {}) or {}
        ruta = cfg.get("ruta")
        if not ruta or not Path(ruta).exists():
            return [Hallazgo(
                "H3-HOST", "H3-HOST-SIN-RUTA",
                "No se declaró una ruta local que escanear con Trivy",
                Severidad.INFO, "informativo", str(ruta) if ruta else "",
                "Declara host_trivy.ruta (p. ej. el directorio del despliegue) para el "
                "escaneo de vulnerabilidades/secretos/config.", REFS_SUPPLY)]

        escaneres = cfg.get("escaneres", ["vuln", "misconfig", "secret"])
        severidad = cfg.get("severidad", "CRITICAL,HIGH,MEDIUM,LOW")
        cache = objetivo.get("herramientas", {}).get("trivy", {}).get("cache_dir")

        cmd = [
            det.ruta, "fs", "--quiet", "--format", "json",
            "--scanners", ",".join(escaneres),
            "--severity", severidad,
            "--skip-db-update", "--skip-java-db-update", "--offline-scan",
        ]
        if cache:
            cmd += ["--cache-dir", cache]
        cmd += [ruta]

        res = herramientas.ejecutar(cmd, timeout=self._timeout(objetivo, 900))

        if res.expiro:
            return [Hallazgo(
                "H3-HOST", "H3-HOST-TIMEOUT",
                "El escaneo con Trivy agotó el tiempo límite",
                Severidad.MEDIA, "informativo",
                f"timeout tras {self._timeout(objetivo, 900)} s escaneando {ruta}",
                "Aumenta herramientas.trivy.timeout o reduce el alcance (host_trivy.ruta).",
                REFS_SUPPLY)]

        if res.error or (res.returncode not in (0,) and not res.stdout.strip()):
            return [Hallazgo(
                "H3-HOST", "H3-HOST-ERROR",
                "Trivy terminó con un error",
                Severidad.MEDIA, "informativo",
                res.error or f"returncode {res.returncode}",
                "Revisa la instalación de Trivy y que la ruta sea accesible; ejecuta "
                "'trivy fs' manualmente para ver el detalle.", REFS_SUPPLY)]

        try:
            obj = json.loads(res.stdout)
        except (ValueError, TypeError) as e:
            return [Hallazgo(
                "H3-HOST", "H3-HOST-ERROR",
                "No se pudo interpretar la salida JSON de Trivy",
                Severidad.MEDIA, "informativo", f"{type(e).__name__}",
                "Comprueba la versión de Trivy; MRRobot espera la salida de "
                "'trivy fs --format json'.", REFS_SUPPLY)]

        hallazgos = _hallazgos_desde_trivy(obj)
        # Honestidad sobre el envejecimiento de la DB: se escanea offline.
        hallazgos.insert(0, Hallazgo(
            "H3-HOST", "H3-HOST-OFFLINE",
            "Escaneo con la base de datos de Trivy en modo offline",
            Severidad.INFO, "informativo",
            "escaneo con DB offline; refréscala periódicamente",
            "Refresca la base de vulnerabilidades periódicamente "
            "(p. ej. 'trivy image --download-db-only') para no perder CVEs recientes.",
            REFS_SUPPLY))
        return hallazgos
