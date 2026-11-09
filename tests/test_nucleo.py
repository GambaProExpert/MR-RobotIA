"""Pruebas del núcleo: autorización (deniega por defecto) e informe (md/json)."""
import json

import pytest

from mrrobotia import nucleo
from mrrobotia.nucleo import Informe, Hallazgo, Severidad, ErrorAutorizacion


def _escribir(tmp_path, datos):
    ruta = tmp_path / "objetivo.json"
    ruta.write_text(json.dumps(datos), encoding="utf-8")
    return ruta


def test_cargar_objetivo_deniega_sin_autorizacion(tmp_path):
    ruta = _escribir(tmp_path, {"nombre": "x", "autorizacion": {"tengo_autorizacion": False}})
    with pytest.raises(ErrorAutorizacion):
        nucleo.cargar_objetivo(ruta)


def test_cargar_objetivo_deniega_sin_clave_autorizacion(tmp_path):
    ruta = _escribir(tmp_path, {"nombre": "x"})
    with pytest.raises(ErrorAutorizacion):
        nucleo.cargar_objetivo(ruta)


def test_cargar_objetivo_deniega_host_no_local_sin_confirmar(tmp_path):
    ruta = _escribir(tmp_path, {
        "nombre": "x",
        "host": "192.168.1.50",
        "autorizacion": {
            "tengo_autorizacion": True,
            "autorizado_por": "Sergio",
            "ambito": "lab",
            "fecha": "2026-11-06",
        },
    })
    with pytest.raises(ErrorAutorizacion):
        nucleo.cargar_objetivo(ruta)


def test_cargar_objetivo_acepta_valido(tmp_path):
    datos = {
        "nombre": "Objetivo válido",
        "host": "127.0.0.1",
        "autorizacion": {
            "tengo_autorizacion": True,
            "autorizado_por": "Sergio",
            "ambito": "lab del TFG",
            "fecha": "2026-11-06",
        },
    }
    ruta = _escribir(tmp_path, datos)
    objetivo = nucleo.cargar_objetivo(ruta)
    assert objetivo["nombre"] == "Objetivo válido"
    assert objetivo["autorizacion"]["autorizado_por"] == "Sergio"


def test_cargar_objetivo_acepta_host_no_local_confirmado(tmp_path):
    datos = {
        "nombre": "remoto",
        "host": "10.0.0.5",
        "autorizacion": {
            "tengo_autorizacion": True,
            "autorizado_por": "Sergio",
            "ambito": "lab",
            "fecha": "2026-11-06",
            "confirmo_no_local": True,
        },
    }
    ruta = _escribir(tmp_path, datos)
    objetivo = nucleo.cargar_objetivo(ruta)
    assert objetivo["host"] == "10.0.0.5"


def test_informe_genera_markdown_y_json():
    objetivo = {
        "nombre": "Prueba",
        "autorizacion": {
            "tengo_autorizacion": True,
            "autorizado_por": "Sergio",
            "ambito": "lab",
            "fecha": "2026-11-06",
        },
    }
    informe = Informe(objetivo)
    informe.modulos_ejecutados.append("M2")
    informe.anadir([
        Hallazgo("M2", "M2-OK-x", "Integridad verificada: x", Severidad.INFO,
                 "informativo", "sha256 abc…"),
        Hallazgo("M2", "M2-ALTERADO-y", "Artefacto alterado: y", Severidad.CRITICA,
                 "confirmado", "esperado a…, real b…", "No cargar el artefacto."),
    ])

    md = informe.to_markdown()
    assert md.startswith("# Informe MRRobotIA")
    assert "Sergio" in md
    assert "CRITICA" in md
    assert "## Recomendaciones" in md

    datos = json.loads(informe.to_json())
    assert datos["herramienta"] == "MRRobotIA"
    assert datos["autorizado_por"] == "Sergio"
    # la autorización no debe volcarse dentro del objetivo del informe
    assert "autorizacion" not in datos["objetivo"]
    # ordenado por severidad descendente: la CRITICA va primero
    assert datos["hallazgos"][0]["severidad"] == "CRITICA"
    assert datos["hallazgos"][0]["modulo"] == "M2"


def test_informe_marca_lo_sin_concluir():
    inf = Informe({"nombre": "x", "autorizacion": {"autorizado_por": "a", "ambito": "b"}})
    inf.anadir([Hallazgo("M", "X", "Sin dato", Severidad.INFO, "sin_concluir", "e")])
    assert "Sin dato *(sin concluir)*" in inf.to_markdown()


def test_informe_marca_lo_potencial():
    obj = {"nombre": "x", "autorizacion": {"autorizado_por": "x", "ambito": "x"}}
    informe = Informe(obj)
    informe.anadir([Hallazgo("H", "A", "Coincide por versión", Severidad.ALTA, "potencial", "e"),
                    Hallazgo("H", "B", "Observado", Severidad.ALTA, "confirmado", "e")])
    md = informe.to_markdown()
    assert "Coincide por versión *(potencial)*" in md and "Observado *(potencial)*" not in md
