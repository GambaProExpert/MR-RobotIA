"""Pruebas de `cve.py` y de H2-CVE: comparación de versiones, reparto de avisos y agrupación."""
from pathlib import Path

import pytest

from mrrobotia import cve
from mrrobotia.contexto import Contexto, ServidorDetectado
from mrrobotia.modulos.h2_cve import H2Cve
from mrrobotia.nucleo import Severidad
from mrrobotia.perfiles import GENERICO, PERFILES

LLAMA, VLLM = PERFILES
AVISOS = cve.cargar("cve_llamacpp.json")


def aviso(afecta, corregido_en=None, resumen="[llama-server] algo", severidad="ALTA", id_="CVE-X"):
    return {"id": id_, "resumen": resumen, "afecta": afecta, "corregido_en": corregido_en, "cvss": 7.5, "severidad": severidad, "fuente": "u"}


def estado(version, afecta, corregido_en=None):
    return cve.estado_aviso(version, aviso(afecta, corregido_en), cve.clave_build)


# ------------------------------------------------------------------- clave de build
@pytest.mark.parametrize("version,esperado", [
    ("b11583-988015788", 11583), ("b11583", 11583), ("b0-unknown", None), ("b0", None), ("b12-XYZ", None),
    ("0.6.0", None), ("", None), (None, None),
])
def test_clave_build(version, esperado):
    assert cve.clave_build(version) == esperado


# --------------------------------------------------------------------- estado
@pytest.mark.parametrize("version,afecta,corregido,esperado", [
    # Con corrección: dentro, afectada; fuera, no.
    ("b100", "<b200", "b200", cve.AFECTADA),
    ("b200", "<b200", "b200", cve.NO_AFECTADA),
    ("b300", "<b200", "b200", cve.NO_AFECTADA),
    ("b150", ">=b100,<b200", "b200", cve.AFECTADA),
    ("b50", ">=b100,<b200", "b200", cve.NO_AFECTADA),
    # Sin corrección: por encima del límite probado, indeterminada.
    ("b100", "<=b100", None, cve.AFECTADA),
    ("b101", "<=b100", None, cve.INDETERMINADA),
    ("b150", ">=b100,<=b200", None, cve.AFECTADA),
    ("b300", ">=b100,<=b200", None, cve.INDETERMINADA),
    # Antes del inicio del rango no hay duda posible.
    ("b50", ">=b100,<=b200", None, cve.NO_AFECTADA),
])
def test_estado_aviso(version, afecta, corregido, esperado):
    assert estado(version, afecta, corregido) == esperado


def test_comparacion_numerica_y_no_de_cadenas():
    # Con subcadenas, «b115» coincidiría con «b11583».
    assert estado("b11583", "=b115", "b116") == cve.NO_AFECTADA
    assert estado("b11583", "<b9000", "b9000") == cve.NO_AFECTADA
    assert estado("b9", "<b1000", "b1000") == cve.AFECTADA


def test_version_no_interpretable_es_indeterminada():
    assert estado("b0-unknown", "<b200", "b200") == cve.INDETERMINADA
    assert estado("x", "<b200", "b200") == cve.INDETERMINADA


def test_expresion_no_interpretable_es_indeterminada():
    assert estado("b100", "basura", "b200") == cve.INDETERMINADA
    assert estado("b100", "", "b200") == cve.INDETERMINADA
    assert cve.estado_aviso("b100", {"id": "X"}, cve.clave_build) == cve.INDETERMINADA


def test_alternativas_preparadas_para_otros_productos():
    """La sintaxis `||` no depende del producto: basta con pasar otra `clave_version`."""
    entero = lambda v: int(v) if str(v).isdigit() else None
    avisado = aviso(">=1,<3 || >=5,<7", "7")
    assert cve.estado_aviso("2", avisado, entero) == cve.AFECTADA
    assert cve.estado_aviso("6", avisado, entero) == cve.AFECTADA
    assert cve.estado_aviso("4", avisado, entero) == cve.NO_AFECTADA


# ------------------------------------------------------------------- severidad
@pytest.mark.parametrize("valores,esperado", [
    ({"severidad": "CRITICA"}, Severidad.CRITICA), ({"severidad": "alta"}, Severidad.ALTA),
    ({"severidad": None, "cvss": 9.8}, Severidad.CRITICA), ({"cvss": 7.0}, Severidad.ALTA), ({"cvss": 5.3}, Severidad.MEDIA),
    ({"cvss": 3.3}, Severidad.BAJA), ({}, Severidad.MEDIA), ({"severidad": "rara", "cvss": None}, Severidad.MEDIA),
])
def test_severidad_de(valores, esperado):
    assert cve.severidad_de(valores) == esperado


@pytest.mark.parametrize("resumen,esperado", [("[rpc] algo", "rpc"), ("[slot-restore] a", "slot-restore"), ("sin marca", None), ("", None)])
def test_componente(resumen, esperado):
    assert cve.componente({"resumen": resumen}) == esperado


# ------------------------------------------------------------ datos publicados
def test_cargar_nunca_lanza(tmp_path):
    assert cve.cargar("no-existe.json") == []
    assert cve.cargar(None) == []


def test_base_de_avisos_de_llamacpp():
    assert len(AVISOS) == 48
    for a in AVISOS:
        assert a["id"].startswith("CVE-") and cve.severidad_de(a) in Severidad and cve.componente(a), a["id"]
        assert cve.estado_aviso("b11583", a, cve.clave_build) in (cve.AFECTADA, cve.NO_AFECTADA, cve.INDETERMINADA)


def test_base_sin_rutas_locales():
    texto = (Path(cve.DIR_DATOS) / "cve_llamacpp.json").read_text(encoding="utf-8")
    assert "F:\\" not in texto and "TFG_IA" not in texto


def test_resultado_documentado_para_b11583():
    r = cve.clasificar("b11583-988015788", AVISOS, cve.clave_build)
    assert sorted(a["id"] for a in r.afectados) == ["CVE-2026-116096", "CVE-2026-116467", "CVE-2026-118375", "CVE-2026-119052"]
    assert len(r.indeterminados) == 20 and r.no_aplican == []


# ------------------------------------------------------------ componente en uso
def servidor(version="b11583-988015788", opciones=None, entorno=None, tipo="llama.cpp"):
    return ServidorDetectado(tipo, "h", 1, version=version, opciones=opciones or {}, entorno=entorno or {})


def test_rpc_sin_opcion_no_esta_en_uso():
    a = aviso("<b9", resumen="[rpc] algo")
    assert LLAMA.componente_en_uso(a, servidor(opciones={"model": "m"})) is False
    assert LLAMA.componente_en_uso(a, servidor(opciones={"rpc": True})) is True
    assert LLAMA.componente_en_uso(a, servidor(entorno={"LLAMA_ARG_RPC": True})) is True


def test_uso_desconocido_sin_datos_de_arranque():
    assert LLAMA.componente_en_uso(aviso("<b9", resumen="[rpc] a"), servidor()) is None


def test_android_nunca_aplica():
    assert LLAMA.componente_en_uso(aviso("<b9", resumen="[android-jni] a"), servidor()) is False


def test_componentes_siempre_en_uso():
    for marca in ("gguf", "llama-server", "gramatica", "tokenizador", "jinja", "lib"):
        assert LLAMA.componente_en_uso(aviso("<b9", resumen=f"[{marca}] a"), servidor()) is True


def test_multimodal_sin_confirmar():
    assert LLAMA.componente_en_uso(aviso("<b9", resumen="[mtmd] a"), servidor(opciones={"model": "m"})) is None


def test_slot_restore_depende_de_la_opcion():
    a = aviso("<b9", resumen="[slot-restore] a")
    assert LLAMA.componente_en_uso(a, servidor(opciones={"model": "m"})) is False
    assert LLAMA.componente_en_uso(a, servidor(opciones={"slot_save_path": "x"})) is True


@pytest.mark.parametrize("valor,esperado", [("30", True), ("-1", False)])
def test_sueno_depende_de_la_opcion(valor, esperado):
    a = aviso("<=b9060", resumen="[llama-server] a", id_="CVE-2026-43631")
    assert LLAMA.componente_en_uso(a, servidor(opciones={"sleep_idle_seconds": valor})) is esperado


def test_rerank_depende_de_la_opcion():
    a = aviso("<=b9053", resumen="[llama-server] a", id_="CVE-2026-52132")
    assert LLAMA.componente_en_uso(a, servidor(opciones={"reranking": True})) is True
    assert LLAMA.componente_en_uso(a, servidor(opciones={"model": "m"})) is False


# ------------------------------------------------------------------------ módulo
def ejecutar(*servidores):
    m = H2Cve()
    m.contexto = Contexto("linux", servidores=list(servidores))
    return m.ejecutar({})


def por_id(hallazgos):
    return {h.id: h for h in hallazgos}


def test_sin_contexto():
    h = H2Cve().ejecutar({})
    assert [x.id for x in h] == ["H2-CVE-SIN-CONTEXTO"] and h[0].severidad == Severidad.INFO


def test_sin_servidores():
    assert [x.id for x in ejecutar()] == ["H2-CVE-SIN-DATOS"]


def test_grupos_por_severidad_con_opciones_conocidas():
    h = por_id(ejecutar(servidor(opciones={"model": "m"})))
    # Los dos RPC no cuentan: el servidor no se arrancó con --rpc.
    media = h["H2-CVE-MEDIA"]
    assert (media.severidad, media.estado) == (Severidad.MEDIA, "potencial")
    assert "CVE-2026-116467 [llama-server]" in media.evidencia and "CVE-2026-116096 [mtmd]" in media.evidencia
    assert "sin confirmar si se usa: mtmd" in media.evidencia
    assert "H2-CVE-ALTA" not in h and "CVE-2026-118375 [rpc]" in h["H2-CVE-NO-APLICA"].evidencia


def test_sin_datos_de_arranque_cuentan_y_lo_avisa():
    h = por_id(ejecutar(servidor()))
    alta = h["H2-CVE-ALTA"]
    assert "CVE-2026-118375" in alta.evidencia and "sin confirmar si se usa: rpc" in alta.evidencia


def test_indeterminados_son_info_y_nunca_vulnerables():
    h = por_id(ejecutar(servidor(opciones={"model": "m"})))
    ind = h["H2-CVE-INDETERMINADOS"]
    assert ind.severidad == Severidad.INFO and "CVE-2026-43627" in ind.evidencia
    assert "CVE-2026-43627" not in h["H2-CVE-MEDIA"].evidencia


def test_recomendacion_con_la_correccion_mas_alta():
    h = por_id(ejecutar(servidor()))
    assert "b11935" in h["H2-CVE-ALTA"].recomendacion


def test_sin_correccion_lo_dice(monkeypatch):
    monkeypatch.setattr(cve, "cargar", lambda f: [aviso("<=b200000")])
    assert "No consta corrección" in por_id(ejecutar(servidor()))["H2-CVE-ALTA"].recomendacion


def test_ningun_aviso_coincide(monkeypatch):
    monkeypatch.setattr(cve, "cargar", lambda f: [aviso("<b5", "b5")])
    h = por_id(ejecutar(servidor()))
    assert h["H2-CVE-SIN-COINCIDENCIAS"].severidad == Severidad.INFO and "no garantiza" in h["H2-CVE-SIN-COINCIDENCIAS"].recomendacion


def test_sin_version():
    h = ejecutar(servidor(version=None))
    assert [x.id for x in h] == ["H2-CVE-SIN-VERSION"] and h[0].severidad == Severidad.INFO


def test_version_no_comparable():
    h = ejecutar(servidor(version="b0-unknown"))
    assert [x.id for x in h] == ["H2-CVE-SIN-VERSION"] and "b0-unknown" in h[0].evidencia


def test_perfil_generico_sin_base():
    assert [x.id for x in ejecutar(servidor(tipo="generico"))] == ["H2-CVE-SIN-BASE"]
    assert GENERICO.fichero_cve is None


def test_perfil_sin_comparador():
    """vLLM tiene base de avisos, pero aún no su comparación: no se presenta como vulnerable."""
    assert [x.id for x in ejecutar(servidor(tipo="vllm", version="0.33.0"))] == ["H2-CVE-SIN-BASE"]
    assert VLLM.clave_version is None


def test_varios_servidores_rotulados():
    h = ejecutar(servidor(version=None), ServidorDetectado("llama.cpp", "h", 2, version=None))
    assert all(x.evidencia.startswith("llama.cpp en h:") for x in h) and len(h) == 2


def test_un_fallo_no_llega_al_llamador(monkeypatch):
    def falla(f):
        raise RuntimeError("fallo")

    monkeypatch.setattr(cve, "cargar", falla)
    assert [x.id for x in ejecutar(servidor())] == ["H2-CVE-ERROR"]
