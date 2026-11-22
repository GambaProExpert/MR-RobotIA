"""Pruebas de `mrrobotia --check-tools` y del catálogo único de instalación (`instalacion.py`).

Herméticas: la detección de herramientas está simulada y no se ejecuta ni instala nada.
"""
import json
import sys

import pytest

from mrrobotia import cli, herramientas, instalacion
from mrrobotia.herramientas import Deteccion, Herramienta
from mrrobotia.modulos.h2_identificacion import JULIUS
from mrrobotia.modulos.h3_host import H3Host
from mrrobotia.modulos.h3_ssh import SSH_AUDIT
from mrrobotia.modulos.h4_garak import H4Garak
from mrrobotia.modulos.h5_deepteam import DEEPTEAM
from mrrobotia.modulos.h5_promptfoo import NODE, PROMPTFOO

TODAS = [JULIUS, SSH_AUDIT, H3Host.herramienta, H4Garak.herramienta, NODE, PROMPTFOO, DEEPTEAM]


@pytest.fixture
def simulada(monkeypatch):
    """Detección simulada: `estado[nombre]` = (version, ruta) si está instalada; ausente si no está."""
    estado = {}

    def falsa(herramienta, overrides=None, env=None):
        if herramienta.nombre in estado:
            version, ruta = estado[herramienta.nombre]
            return Deteccion(True, version, ruta, None)
        return Deteccion(False, None, None, "no encontrada en PATH")

    monkeypatch.setattr(herramientas, "detectar", falsa)
    return estado


def correr(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["mrrobotia", "--check-tools", *args])
    cli.main()
    return capsys.readouterr().out


def bloque(salida, nombre):
    """Texto de la sección de una herramienta."""
    partes = salida.split("\n\n")
    return next(p for p in partes if p.lstrip().startswith(nombre + ":"))


# ---------------------------------------------------------------------------- presente / ausente
def test_herramienta_presente_con_ruta_y_version(simulada, monkeypatch, capsys):
    simulada["trivy"] = ("0.76.2", "/usr/bin/trivy")
    s = bloque(correr(monkeypatch, capsys), "trivy")
    assert s.startswith("trivy: OK")
    assert "/usr/bin/trivy" in s and "0.76.2" in s
    assert "H3-HOST (scan 'vulns')" in s


def test_herramienta_ausente_da_la_instalacion_exacta(simulada, monkeypatch, capsys):
    s = bloque(correr(monkeypatch, capsys, "--os", "windows"), "trivy")
    assert s.startswith("trivy: NOT INSTALLED")
    assert "trivy_0.76.2_windows-64bit.zip" in s            # versión fijada
    assert "Get-FileHash" in s and "SHA-256 mismatch" in s  # verificación de integridad
    assert "TRIVY_CACHE_DIR" in s and "--download-db-only" in s
    assert "{version}" not in s


def test_sin_objetivo_y_resumen_final(simulada, monkeypatch, capsys):
    simulada["julius"] = (None, "/x/julius")
    out = correr(monkeypatch, capsys)
    assert "1 of 7 tools ready" in out and instalacion.GUIA in out
    assert "not reported by the tool" in bloque(out, "julius")      # Julius no informa de su versión


def test_cada_escaneo_con_su_herramienta(simulada, monkeypatch, capsys):
    out = correr(monkeypatch, capsys)
    for nombre, uso in [("julius", "H2-ID (scan 'id')"), ("ssh-audit", "H3-SSH (scan 'ssh')"),
                        ("trivy", "H3-HOST (scan 'vulns')"), ("garak", "H4-GARAK (scan 'garak')"),
                        ("node", "H5-PROMPTFOO (scan 'promptfoo')"), ("promptfoo", "H5-PROMPTFOO (scan 'promptfoo')")]:
        assert uso in bloque(out, nombre)


# ---------------------------------------------------------------------------- versión
def test_version_insuficiente_se_marca(simulada, monkeypatch, capsys):
    simulada["garak"] = ("0.16.0", "/x/garak")
    s = bloque(correr(monkeypatch, capsys), "garak")
    assert s.startswith("garak: VERSION TOO OLD") and "minimum: 0.17.0" in s
    simulada["garak"] = ("0.17.0", "/x/garak")
    assert bloque(correr(monkeypatch, capsys), "garak").startswith("garak: OK")


def test_version_ilegible_con_minimo_se_avisa(simulada, monkeypatch, capsys):
    simulada["garak"] = (None, "/x/garak")
    assert bloque(correr(monkeypatch, capsys), "garak").startswith("garak: VERSION UNREADABLE")


# ---------------------------------------------------------------------------- sistema operativo simulado
@pytest.mark.parametrize("so,marca,ausente", [
    ("windows", "Invoke-WebRequest", "sha256sum"),
    ("linux", "sha256sum -c -", "Invoke-WebRequest"),
    ("macos", "shasum -a 256 -c -", "Invoke-WebRequest"),
])
def test_instrucciones_segun_el_sistema(simulada, monkeypatch, capsys, so, marca, ausente):
    out = correr(monkeypatch, capsys, "--os", so)
    assert f"instructions for: {so}" in out
    assert marca in bloque(out, "julius") and ausente not in bloque(out, "julius")


def test_sistema_actual_por_defecto(simulada, monkeypatch, capsys):
    monkeypatch.setattr(instalacion.sys, "platform", "darwin")
    assert "instructions for: macos" in correr(monkeypatch, capsys)
    monkeypatch.setattr(instalacion.sys, "platform", "linux")
    assert "instructions for: linux" in correr(monkeypatch, capsys)
    monkeypatch.setattr(instalacion.sys, "platform", "win32")
    assert "instructions for: windows" in correr(monkeypatch, capsys)


def test_os_sin_check_tools_es_un_error(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["mrrobotia", "--os", "linux"])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert "--check-tools" in str(e.value)


# ---------------------------------------------------------------------------- rutas del objetivo
def test_ruta_declarada_en_el_objetivo(monkeypatch, capsys, tmp_path):
    # Detección real: el propio intérprete hace de «trivy» (acepta --version) y otro fichero no existe.
    objetivo = tmp_path / "t.json"
    objetivo.write_text(json.dumps({"tools": {
        "trivy": {"path": sys.executable}, "garak": {"path": str(tmp_path / "no_existe")}}}), encoding="utf-8")
    out = correr(monkeypatch, capsys, "-t", str(objetivo))
    assert "target file (tools.trivy.path)" in bloque(out, "trivy")
    assert "garak: NOT INSTALLED" in out and "does not point to a file" in bloque(out, "garak")


def test_objetivo_ilegible_o_invalido(monkeypatch, capsys, tmp_path):
    malo = tmp_path / "malo.json"
    malo.write_text("{no es json", encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        correr(monkeypatch, capsys, "-t", str(malo))
    assert "not valid JSON" in str(e.value)
    with pytest.raises(SystemExit) as e:
        correr(monkeypatch, capsys, "-t", str(tmp_path / "no_esta.json"))
    assert "Cannot read" in str(e.value)


# ---------------------------------------------------------------------------- una sola fuente de verdad
@pytest.mark.parametrize("h", TODAS, ids=lambda h: h.nombre)
@pytest.mark.parametrize("so", instalacion.SISTEMAS)
def test_catalogo_completo(h, so):
    pasos = instalacion.pasos(h, so)
    assert pasos, f"{h.nombre} sin pasos para {so}"
    assert pasos[0].recomendada and pasos[0].resumen and pasos[0].ordenes
    assert h.fijada, "la versión fijada se lee de la Herramienta"
    for p in pasos:
        assert "{version}" not in " ".join((p.titulo, p.fuente, p.binario, p.resumen, *p.ordenes))
        assert p.fuente.startswith("https://")


@pytest.mark.parametrize("h", [H3Host.herramienta, JULIUS], ids=lambda h: h.nombre)
@pytest.mark.parametrize("so", instalacion.SISTEMAS)
def test_binarios_verifican_la_suma(h, so):
    ordenes = " ".join(instalacion.pasos(h, so)[0].ordenes)
    assert ("Get-FileHash" in ordenes) if so == "windows" else ("sha256sum" in ordenes or "shasum" in ordenes)


@pytest.mark.parametrize("h", TODAS, ids=lambda h: h.nombre)
def test_el_info_de_ausente_usa_el_mismo_texto_que_check_tools(h, monkeypatch):
    """El hallazgo INFO y --check-tools salen del mismo catálogo: el resumen del paso recomendado."""
    for so in instalacion.SISTEMAS:
        monkeypatch.setattr(instalacion, "sistema_actual", lambda so=so: so)
        assert instalacion.pasos(h, so)[0].resumen in herramientas.como_instalar(h)
        assert f"tools.{h.nombre}.path" in herramientas.como_instalar(h)


def test_no_se_repite_la_instalacion_en_los_modulos():
    """Ningún módulo lleva ya su propio texto de instalación: todo sale del catálogo."""
    for h in TODAS:
        assert h.instalar_con == ""


def test_herramienta_fuera_del_catalogo_usa_su_texto():
    h = Herramienta("mx", "mx", instalar_con="pip install mx")
    assert instalacion.pasos(h) == [] and "pip install mx" in herramientas.como_instalar(h)


def test_garak_fija_y_exige_las_versiones_del_modulo():
    from mrrobotia.modulos import h4_garak
    h = H4Garak.herramienta
    assert h.fijada == h4_garak.VERSION_PROBADA and h.exigida == h4_garak.VERSION_MINIMA
    assert f"garak=={h4_garak.VERSION_PROBADA}" in " ".join(instalacion.pasos(h, "linux")[0].ordenes)


# ---------------------------------------------------------------------------- guía pública
@pytest.mark.parametrize("fichero", ["docs/TOOLS.md", "docs/HERRAMIENTAS.md"])
def test_la_guia_publica_lleva_las_ordenes_del_catalogo(fichero):
    """La guía se genera del catálogo: cada orden del catálogo (todos los sistemas) está en ella."""
    from pathlib import Path
    texto = (Path(__file__).resolve().parent.parent / fichero).read_text(encoding="utf-8")
    for h in TODAS:
        for so in instalacion.SISTEMAS:
            for p in instalacion.pasos(h, so):
                for orden in p.ordenes:
                    assert orden in texto, f"{fichero}: falta «{orden}» ({h.nombre}, {so})"
    for privado in ("Usuario", "TFG_IA", "MRRobot_lab"):
        assert privado not in texto
