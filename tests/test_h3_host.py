"""Pruebas de H3 (Trivy): normalización de la salida y, sobre todo, la garantía
de que el VALOR de un secreto NUNCA aparece en el informe.

No requieren Trivy instalado: la función de normalización es pura (se le pasa un
dict fabricado) y las rutas de ejecución se simulan sustituyendo
`herramientas.ejecutar`. Nada se descarga ni se ejecuta contra disco real.
"""
import json
import types

from mrrobotia import herramientas
from mrrobotia.herramientas import Resultado
from mrrobotia.modulos.h3_host import H3Host, _hallazgos_desde_trivy
from mrrobotia.nucleo import Severidad


# Valor de secreto de juguete que JAMÁS debe acabar en un hallazgo.
SECRETO = "AKIASECRETVALUE123"


def _todos_los_campos(hallazgos):
    """Concatena TODOS los campos de texto de todos los hallazgos, para poder
    afirmar que una cadena prohibida no se cuela en ninguno."""
    trozos = []
    for h in hallazgos:
        trozos += [h.modulo, h.id, h.titulo, h.severidad.name, h.estado,
                   h.evidencia, h.recomendacion, repr(h.refs)]
    return "\n".join(trozos)


def test_normaliza_cve_y_secreto_sin_filtrar_el_valor():
    obj = {
        "Results": [
            {
                "Target": "deploy/package-lock.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.2",
                        "FixedVersion": "3.0.14",
                        "Severity": "CRITICAL",
                        "Title": "openssl: buffer overflow",
                    }
                ],
            },
            {
                "Target": "deploy/.env",
                "Secrets": [
                    {
                        "RuleID": "aws-access-key",
                        "Severity": "CRITICAL",
                        "StartLine": 4,
                        # Trivy trae el valor en Match/Code: NO debe propagarse.
                        "Match": SECRETO,
                        "Code": {"Lines": [{"Content": SECRETO}]},
                    }
                ],
            },
        ]
    }

    hallazgos = _hallazgos_desde_trivy(obj)
    por_id = {h.id: h for h in hallazgos}

    # El CVE se mapea con su id y severidad CRÍTICA.
    assert "H3-HOST-CVE-CVE-2024-0001" in por_id
    assert por_id["H3-HOST-CVE-CVE-2024-0001"].severidad == Severidad.CRITICA

    # El secreto se reporta por regla + fichero:línea.
    assert "H3-HOST-SECRET-aws-access-key" in por_id
    secreto = por_id["H3-HOST-SECRET-aws-access-key"]
    assert secreto.evidencia == "aws-access-key en deploy/.env:4"

    # INVARIANTE DURO: el valor del secreto no aparece en NINGÚN campo de NINGÚN hallazgo.
    assert SECRETO not in _todos_los_campos(hallazgos)


def test_sin_hallazgos_devuelve_limpio():
    hallazgos = _hallazgos_desde_trivy({"Results": []})
    assert len(hallazgos) == 1
    assert hallazgos[0].id == "H3-HOST-LIMPIO"
    assert hallazgos[0].severidad == Severidad.INFO


def test_misconfig_se_normaliza():
    obj = {
        "Results": [
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "DS002",
                        "AVDID": "AVD-DS-0002",
                        "Title": "Image user should not be 'root'",
                        "Severity": "HIGH",
                        "Resolution": "Add 'USER <non root user>' to the Dockerfile",
                    }
                ],
            }
        ]
    }
    por_id = {h.id: h for h in _hallazgos_desde_trivy(obj)}
    assert "H3-HOST-MISCONFIG-DS002" in por_id
    assert por_id["H3-HOST-MISCONFIG-DS002"].severidad == Severidad.ALTA
    assert "Dockerfile" in por_id["H3-HOST-MISCONFIG-DS002"].evidencia


def test_trunca_por_categoria_y_resume():
    muchas = [
        {"VulnerabilityID": f"CVE-X-{i}", "PkgName": "p", "InstalledVersion": "1",
         "FixedVersion": "2", "Severity": "LOW", "Title": "t"}
        for i in range(30)
    ]
    hallazgos = _hallazgos_desde_trivy({"Results": [{"Target": "t", "Vulnerabilities": muchas}]})
    cves = [h for h in hallazgos if h.id.startswith("H3-HOST-CVE-")]
    assert len(cves) == 25                      # recortado a MAX_POR_CATEGORIA
    assert any(h.id == "H3-HOST-RESUMEN" for h in hallazgos)


# --- Rutas de ejecución, SIN Trivy real (se sustituye herramientas.ejecutar) -----

_DET = types.SimpleNamespace(ruta="trivy", version="0.50.0", disponible=True, error=None)


def test_auditar_sin_ruta_declarada():
    """Sin host_trivy.ruta en el objetivo, un INFO 'SIN-RUTA' (no se ejecuta nada)."""
    hallazgos = H3Host()._auditar({}, _DET)
    assert len(hallazgos) == 1
    assert hallazgos[0].id == "H3-HOST-SIN-RUTA"
    assert hallazgos[0].severidad == Severidad.INFO


def test_auditar_ejecucion_ok_antepone_offline(tmp_path, monkeypatch):
    salida = json.dumps({"Results": [{
        "Target": "x", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2024-0002", "PkgName": "zlib",
            "InstalledVersion": "1.2.0", "FixedVersion": "1.3", "Severity": "HIGH",
            "Title": "zlib bug"}]}]})
    monkeypatch.setattr(herramientas, "ejecutar",
                        lambda *a, **k: Resultado(0, salida, "", False, None))

    objetivo = {"host_trivy": {"ruta": str(tmp_path)}}
    hallazgos = H3Host()._auditar(objetivo, _DET)
    assert hallazgos[0].id == "H3-HOST-OFFLINE"            # contexto de honestidad primero
    assert any(h.id == "H3-HOST-CVE-CVE-2024-0002" for h in hallazgos)


def test_auditar_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(herramientas, "ejecutar",
                        lambda *a, **k: Resultado(None, "", "", True, "timeout"))
    objetivo = {"host_trivy": {"ruta": str(tmp_path)}}
    hallazgos = H3Host()._auditar(objetivo, _DET)
    assert len(hallazgos) == 1
    assert hallazgos[0].id == "H3-HOST-TIMEOUT"
    assert hallazgos[0].severidad == Severidad.MEDIA


def test_auditar_error(tmp_path, monkeypatch):
    monkeypatch.setattr(herramientas, "ejecutar",
                        lambda *a, **k: Resultado(2, "", "boom", False, None))
    objetivo = {"host_trivy": {"ruta": str(tmp_path)}}
    hallazgos = H3Host()._auditar(objetivo, _DET)
    assert len(hallazgos) == 1
    assert hallazgos[0].id == "H3-HOST-ERROR"
    assert hallazgos[0].severidad == Severidad.MEDIA
