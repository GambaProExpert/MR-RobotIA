"""Pruebas de M2: integridad SHA-256 de artefactos contra el manifiesto."""
import json

from mrrobot.modulos.m2_integridad import M2Integridad, sha256_fichero
from mrrobot.nucleo import Severidad


def _crear(ruta, contenido):
    ruta.write_bytes(contenido)
    return ruta


def test_m2_un_hallazgo_por_tipo(tmp_path):
    coincide = _crear(tmp_path / "coincide.gguf", b"artefacto correcto")
    alterado = _crear(tmp_path / "alterado.gguf", b"artefacto realmente distinto")
    sinref = _crear(tmp_path / "sinref.gguf", b"artefacto sin hash de referencia")
    ausente = tmp_path / "ausente.gguf"  # a proposito, no se crea

    sha_ok = sha256_fichero(coincide)

    manif = tmp_path / "manifiesto.json"
    manif.write_text("{}", encoding="utf-8")  # existe pero sin firma

    objetivo = {
        "manifiesto": str(manif),
        "manifiesto_firmado": False,
        "artefactos": [
            {"ruta": str(coincide), "sha256": sha_ok},
            {"ruta": str(alterado), "sha256": "0" * 64},
            {"ruta": str(ausente), "sha256": "0" * 64},
            {"ruta": str(sinref)},
        ],
    }

    hallazgos = M2Integridad().ejecutar(objetivo)
    por_id = {h.id: h for h in hallazgos}

    assert por_id["M2-OK-coincide.gguf"].severidad == Severidad.INFO
    assert por_id["M2-ALTERADO-alterado.gguf"].severidad == Severidad.CRITICA
    assert por_id["M2-FALTA-ausente.gguf"].severidad == Severidad.ALTA
    assert por_id["M2-SINREF-sinref.gguf"].severidad == Severidad.MEDIA
    assert por_id["M2-MANIF-SIN-FIRMA"].severidad == Severidad.MEDIA


def test_m2_manifiesto_firmado_y_hash_desde_manifiesto(tmp_path):
    art = _crear(tmp_path / "modelo.gguf", b"pesos del modelo")
    sha = sha256_fichero(art)
    manif = tmp_path / "manifiesto.json"
    manif.write_text(json.dumps({"modelo.gguf": {"sha256": sha}}), encoding="utf-8")

    objetivo = {
        "manifiesto": str(manif),
        "manifiesto_firmado": True,
        "artefactos": [{"ruta": str(art)}],
    }
    ids = {h.id for h in M2Integridad().ejecutar(objetivo)}
    assert "M2-MANIF-SIN-FIRMA" not in ids   # firmado: no debe avisar
    assert "M2-OK-modelo.gguf" in ids        # hash tomado del manifiesto


def test_m2_manifiesto_ausente_y_sin_artefactos(tmp_path):
    objetivo = {
        "manifiesto": str(tmp_path / "no_existe.json"),
        "artefactos": [],
    }
    por_id = {h.id: h for h in M2Integridad().ejecutar(objetivo)}
    assert por_id["M2-MANIF-FALTA"].severidad == Severidad.ALTA
    assert por_id["M2-SIN-ARTEFACTOS"].severidad == Severidad.INFO
