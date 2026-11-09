"""Pruebas de M2: integridad SHA-256 de artefactos contra el manifiesto."""
import json

from mrrobotia.modulos.m2_integridad import M2Integridad, sha256_fichero
from mrrobotia.nucleo import Severidad


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


def test_m2_sha256_no_valido_no_es_alteracion(tmp_path):
    art = _crear(tmp_path / "modelo.gguf", b"contenido")
    manif = tmp_path / "manifiesto.json"
    manif.write_text(json.dumps({"modelo.gguf": {"sha256": "pon_aqui_un_hash"}}), encoding="utf-8")
    for declarado in ("relleno-que-no-es-un-hash", "ab" * 31, "g" * 64, 12345):
        hallazgos = M2Integridad().ejecutar(
            {"artefactos": [{"ruta": str(art), "sha256": declarado}]})
        assert [h.id for h in hallazgos] == ["M2-SHA-INVALIDO-modelo.gguf"]
        h = hallazgos[0]
        assert (h.severidad, h.estado) == (Severidad.INFO, "sin_concluir")
        assert "no es un SHA-256" in h.evidencia and str(declarado) not in h.evidencia
        assert sha256_fichero(art) in h.evidencia
    # El mismo valor inválido puesto en el manifiesto da el mismo resultado.
    hallazgos = M2Integridad().ejecutar(
        {"manifiesto": str(manif), "manifiesto_firmado": True, "artefactos": [{"ruta": str(art)}]})
    assert [h.id for h in hallazgos] == ["M2-SHA-INVALIDO-modelo.gguf"]


def test_m2_sha256_valido_en_mayusculas_sigue_comparando(tmp_path):
    art = _crear(tmp_path / "modelo.gguf", b"contenido")
    sha = sha256_fichero(art)
    assert [h.id for h in M2Integridad().ejecutar({"artefactos": [{"ruta": str(art), "sha256": sha.upper()}]})] \
        == ["M2-OK-modelo.gguf"]
    assert [h.id for h in M2Integridad().ejecutar({"artefactos": [{"ruta": str(art), "sha256": "0" * 64}]})] \
        == ["M2-ALTERADO-modelo.gguf"]
