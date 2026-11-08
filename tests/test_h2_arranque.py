"""Pruebas de H2-ARRANQUE: severidades de `evaluar_arranque` (tabla de `llamacpp.md` §7) y
módulo, incluido el entorno del propio servidor."""
import pytest

from mrrobotia.contexto import Contexto, ServidorDetectado
from mrrobotia.modulos import h2_arranque as h2a
from mrrobotia.modulos.h2_arranque import H2Arranque
from mrrobotia.nucleo import Severidad
from mrrobotia.perfiles import GENERICO, PERFILES

LLAMA = PERFILES[0]
CANARIO = "canario-no-debe-salir"


def servidor(opciones=None, entorno=None, autenticacion="activa", **kw):
    return ServidorDetectado(**{"tipo": "llama.cpp", "host": "127.0.0.1", "puerto": 1, "opciones": opciones or {},
                                "entorno": entorno or {}, "autenticacion": autenticacion, **kw})


def evaluar(opciones=None, entorno=None, expuesto=False, autenticacion="activa", **kw):
    return LLAMA.evaluar_arranque(servidor(opciones, entorno, autenticacion, **kw), expuesto)


def ids(hallazgos):
    return [h.id for h in hallazgos]


def uno(hallazgos, sufijo):
    id_ = sufijo if sufijo.startswith("H2-") else f"H2-ARRANQUE-{sufijo}"
    encontrados = [h for h in hallazgos if h.id == id_]
    assert len(encontrados) == 1, ids(hallazgos)
    return encontrados[0]


# ------------------------------------------------------------- tabla de severidades
@pytest.mark.parametrize("opciones,entorno,sufijo,loopback,en_red", [
    ({"metrics": True}, {}, "METRICS", Severidad.BAJA, Severidad.MEDIA),
    ({}, {"LLAMA_ARG_ENDPOINT_METRICS": "1"}, "METRICS", Severidad.BAJA, Severidad.MEDIA),
    ({"props": True}, {}, "PROPS", Severidad.BAJA, Severidad.BAJA),
    ({}, {"LLAMA_SERVER_SLOTS_DEBUG": "1"}, "SLOTS-DEBUG", Severidad.ALTA, Severidad.CRITICA),
    ({"media_path": "m"}, {}, "MEDIA-PATH", Severidad.MEDIA, Severidad.MEDIA),
    ({"path": "p"}, {}, "STATIC-PATH", Severidad.MEDIA, Severidad.MEDIA),
    ({"log_prompts_dir": "d"}, {}, "LOG-PROMPTS", Severidad.ALTA, Severidad.ALTA),
    ({"log_verbosity": "5"}, {}, "LOG-VERBOSIDAD", Severidad.MEDIA, Severidad.MEDIA),
    ({"verbose": True}, {}, "LOG-VERBOSIDAD", Severidad.MEDIA, Severidad.MEDIA),
    ({"log_file": "l"}, {}, "LOG-FILE", Severidad.BAJA, Severidad.BAJA),
    ({"rpc": True}, {}, "RPC", Severidad.ALTA, Severidad.ALTA),
    ({"lora": "a.gguf"}, {}, "LORA", Severidad.INFO, Severidad.INFO),
    ({"models_dir": "d"}, {}, "ROUTER", Severidad.INFO, Severidad.ALTA),
    ({"hf_token": True}, {}, "HF-TOKEN", Severidad.MEDIA, Severidad.MEDIA),
    ({"hf_repo": "org/m"}, {}, "DESCARGA", Severidad.BAJA, Severidad.BAJA),
    ({"reuse_port": True}, {}, "REUSE-PORT", Severidad.BAJA, Severidad.BAJA),
    ({"ui_config": True}, {}, "UI-CONFIG", Severidad.BAJA, Severidad.BAJA),
    ({"agent": True}, {}, "AGENTE", Severidad.CRITICA, Severidad.CRITICA),
    ({"mcp_servers_json": True}, {}, "MCP", Severidad.ALTA, Severidad.ALTA),
])
def test_severidades(opciones, entorno, sufijo, loopback, en_red):
    assert uno(evaluar(opciones, entorno), sufijo).severidad == loopback
    assert uno(evaluar(opciones, entorno, expuesto=True), sufijo).severidad == en_red


@pytest.mark.parametrize("valor", ["0"])
def test_slots_debug_a_cero_no_cuenta(valor):
    assert "H2-ARRANQUE-SLOTS-DEBUG" not in ids(evaluar(entorno={"LLAMA_SERVER_SLOTS_DEBUG": valor}))


@pytest.mark.parametrize("verbosidad", ["4", "x", True])
def test_verbosidad_normal_no_cuenta(verbosidad):
    assert "H2-ARRANQUE-LOG-VERBOSIDAD" not in ids(evaluar({"log_verbosity": verbosidad}))


# --------------------------------------------------------------- clave de API
def test_clave_en_la_linea_de_ordenes():
    h = uno(evaluar({"api_key": True}), "CLAVE-EN-ORDEN")
    assert h.severidad == Severidad.MEDIA and "--api-key-file" in h.recomendacion


def test_clave_por_entorno_no_es_llamada_de_atencion():
    h = evaluar(entorno={"LLAMA_API_KEY": True})
    assert "H2-ARRANQUE-CLAVE-EN-ORDEN" not in ids(h) and "H2-ARRANQUE-SIN-CLAVE" not in ids(h)


@pytest.mark.parametrize("expuesto,severidad", [(False, Severidad.MEDIA), (True, Severidad.CRITICA)])
def test_sin_clave_segun_exposicion(expuesto, severidad):
    assert uno(evaluar(autenticacion="abierta", expuesto=expuesto), "SIN-CLAVE").severidad == severidad


def test_sin_clave_confirmado_si_la_red_lo_ve():
    assert uno(evaluar(autenticacion="abierta"), "SIN-CLAVE").estado == "confirmado"


@pytest.mark.parametrize("autenticacion", [None, "indeterminada"])
def test_sin_clave_potencial_si_no_se_ha_comprobado(autenticacion):
    h = uno(evaluar(autenticacion=autenticacion), "SIN-CLAVE")
    assert h.estado == "potencial" and "podría venir del entorno" in h.evidencia


# --------------------------------------------------------------- carencias
def test_carencia_de_no_slots_segun_exposicion():
    assert uno(evaluar(), "SLOTS").severidad == Severidad.BAJA and uno(evaluar(expuesto=True), "SLOTS").severidad == Severidad.MEDIA
    assert uno(evaluar(), "SLOTS").estado == "potencial"
    assert "H2-ARRANQUE-SLOTS" not in ids(evaluar({"slots": False}))
    assert "H2-ARRANQUE-SLOTS" not in ids(evaluar(entorno={"LLAMA_ARG_ENDPOINT_SLOTS": "0"}))


def test_carencia_de_no_webui():
    assert uno(evaluar(), "WEBUI").severidad == Severidad.BAJA and uno(evaluar(expuesto=True), "WEBUI").severidad == Severidad.MEDIA
    assert "H2-ARRANQUE-WEBUI" not in ids(evaluar({"webui": False}))


def test_carencia_de_tls():
    assert uno(evaluar(), "TLS").severidad == Severidad.BAJA and uno(evaluar(expuesto=True), "TLS").severidad == Severidad.ALTA
    assert "H2-ARRANQUE-TLS" not in ids(evaluar({"ssl_cert_file": "c.pem"}))
    assert uno(evaluar(fuentes=["http"]), "TLS").estado == "confirmado" and uno(evaluar(fuentes=["proceso"]), "TLS").estado == "potencial"


# ---------------------------------------------------------------- enlace y CORS
def test_host_fuera_de_loopback():
    assert uno(evaluar({"host": "0.0.0.0"}), "HOST").severidad == Severidad.ALTA
    assert uno(evaluar({"host": "0.0.0.0"}, autenticacion="abierta"), "HOST").severidad == Severidad.CRITICA
    assert uno(evaluar({"host": "127.0.0.1,10.0.0.2"}), "HOST")
    assert uno(evaluar(entorno={"LLAMA_ARG_HOST": "0.0.0.0"}), "HOST")


@pytest.mark.parametrize("opciones", [{"host": "127.0.0.1"}, {"host": "llama.sock"}, {}])
def test_host_en_loopback_o_socket(opciones):
    assert "H2-ARRANQUE-HOST" not in ids(evaluar(opciones))


def test_cors_por_defecto_es_cualquier_origen():
    h = uno(evaluar(), "CORS")
    assert h.severidad == Severidad.MEDIA and h.estado == "potencial" and "valor por defecto" in h.evidencia
    assert uno(evaluar(autenticacion="abierta"), "CORS").severidad == Severidad.ALTA


def test_cors_explicito():
    h = uno(evaluar({"cors_origins": "*"}), "CORS")
    assert h.estado == "confirmado"
    assert uno(evaluar({"cors_origins": "*", "cors_credentials": False}), "CORS").severidad == Severidad.BAJA


def test_cors_restringido_no_es_hallazgo():
    assert "H2-ARRANQUE-CORS" not in ids(evaluar({"cors_origins": "localhost"}))
    assert "H2-ARRANQUE-CORS" not in ids(evaluar({"cors_origins": "https://app.test"}))


def test_cors_lista_literal():
    assert uno(evaluar({"cors_origins": "https://a.test,https://b.test"}), "CORS").severidad == Severidad.BAJA


@pytest.mark.parametrize("opciones", [{"tools": "get_info"}, {"agent": True}, {"mcp_servers_config": "c.json"}])
def test_cors_por_defecto_con_herramientas_es_localhost(opciones):
    assert "H2-ARRANQUE-CORS" not in ids(evaluar(opciones))


# ------------------------------------------------------- herramientas y otros
@pytest.mark.parametrize("valor,severidad", [
    ("get_info", Severidad.ALTA), ("read_file,grep_search", Severidad.ALTA), ("all", Severidad.CRITICA),
    ("read_file,exec_shell_command", Severidad.CRITICA), ("write_file", Severidad.CRITICA), ("edit_file", Severidad.CRITICA),
])
def test_herramientas(valor, severidad):
    assert uno(evaluar({"tools": valor}), "TOOLS").severidad == severidad


def test_proxy_mcp():
    assert uno(evaluar({"ui_mcp_proxy": True}), "MCP-PROXY").severidad == Severidad.ALTA
    assert uno(evaluar({"ui_mcp_proxy": True}, expuesto=True), "MCP-PROXY").severidad == Severidad.CRITICA
    assert uno(evaluar({"ui_mcp_proxy": True}, autenticacion="abierta"), "MCP-PROXY").severidad == Severidad.CRITICA
    assert "H2-ARRANQUE-MCP-PROXY" not in ids(evaluar({"ui_mcp_proxy": False}))


def test_guardado_de_slots():
    assert uno(evaluar({"slot_save_path": "s"}), "SLOT-SAVE").severidad == Severidad.MEDIA
    assert uno(evaluar({"slot_save_path": "s"}, autenticacion="abierta"), "SLOT-SAVE").severidad == Severidad.ALTA


def test_opciones_informativas_en_un_unico_hallazgo():
    h = uno(evaluar({"port": "8080", "ctx_size": "256", "sleep_idle_seconds": "30"}), "OTRAS")
    assert h.severidad == Severidad.INFO and "port=8080" in h.evidencia and "CVE-2026-43631" in h.recomendacion
    assert "H2-ARRANQUE-OTRAS" not in ids(evaluar())
    assert "CVE-2026" not in uno(evaluar({"sleep_idle_seconds": "-1"}), "OTRAS").recomendacion


def test_solo_valores_saneados():
    h = evaluar({"cors_origins": "a,<script>|", "tools": "x|y"})
    assert not any("|" in x.evidencia or "<script" in x.evidencia for x in h)


def test_secreto_nunca_en_la_evidencia():
    opciones = LLAMA.analizar_argv(["llama-server", "--api-key", CANARIO, "--hf-token", CANARIO, "--mcp-servers-json", CANARIO,
                                    "--cors-origins", "*", "--rpc", CANARIO, "-mu", f"https://u:{CANARIO}@h/m"])
    assert CANARIO not in repr(LLAMA.evaluar_arranque(servidor(opciones), True))


def test_generico_no_tiene_opciones():
    assert GENERICO.evaluar_arranque(servidor(), False) == []


# ------------------------------------------------------------------------ módulo
def ejecutar(*servidores):
    m = H2Arranque()
    m.contexto = Contexto("linux", servidores=list(servidores))
    return m.ejecutar({})


def test_sin_contexto():
    h = H2Arranque().ejecutar({})
    assert [x.id for x in h] == ["H2-ARRANQUE-SIN-CONTEXTO"] and h[0].severidad == Severidad.INFO


def test_sin_servidores():
    assert ids(ejecutar()) == ["H2-ARRANQUE-SIN-DATOS"]


def test_sin_opciones_no_evalua():
    h = ejecutar(servidor(pid=None))
    assert "H2-ARRANQUE-SIN-OPCIONES" in ids(h) and "H2-ARRANQUE-SLOTS" not in ids(h)


def test_evalua_con_el_enlace_real():
    h = ejecutar(servidor({"metrics": True}, enlace="todas"))
    assert uno(h, "METRICS").severidad == Severidad.MEDIA and uno(h, "METRICS").evidencia.startswith("llama.cpp en 127.0.0.1:1:")
    h = ejecutar(servidor({"metrics": True}, enlace="loopback"))
    assert uno(h, "METRICS").severidad == Severidad.BAJA


def test_un_fallo_del_perfil_no_llega_al_llamador(monkeypatch):
    def falla(*a):
        raise RuntimeError("fallo")

    monkeypatch.setattr(LLAMA, "evaluar_arranque", falla)
    assert uno(ejecutar(servidor({"metrics": True})), "ERROR").evidencia.endswith("RuntimeError")


# ------------------------------------------------- entorno del propio servidor
def test_evaluar_env():
    h = h2a._evaluar_env(["OPENAI_API_KEY", "HF_TOKEN"])
    assert h.severidad == Severidad.MEDIA and "OPENAI_API_KEY" in h.evidencia and "HF_TOKEN" in h.evidencia
    assert h2a._evaluar_env([]).severidad == Severidad.INFO


def test_env_presencia_sin_valor(monkeypatch):
    monkeypatch.setattr(h2a.procesos, "leer_entorno", lambda pid, v: {"OPENAI_API_KEY": True, "HF_TOKEN": True})
    h = uno(ejecutar(servidor(pid=5)), "H2-ENV")
    assert h.severidad == Severidad.MEDIA and "HF_TOKEN" in h.evidencia and "OPENAI_API_KEY" in h.evidencia


def test_env_legible_sin_claves(monkeypatch):
    monkeypatch.setattr(h2a.procesos, "leer_entorno", lambda pid, v: {})
    monkeypatch.setattr(h2a.procesos, "entorno_legible", lambda pid: True)
    h = uno(ejecutar(servidor(pid=5)), "H2-ENV")
    assert h.severidad == Severidad.INFO and "ninguna" in h.evidencia


def test_env_no_legible_no_afirma_nada(monkeypatch):
    monkeypatch.setattr(h2a.procesos, "leer_entorno", lambda pid, v: {})
    monkeypatch.setattr(h2a.procesos, "entorno_legible", lambda pid: False)
    h = uno(ejecutar(servidor(pid=5)), "H2-ENV")
    assert h.severidad == Severidad.INFO and "no es legible" in h.evidencia and "sin comprobar" in h.titulo


def test_env_del_auditor_no_cuenta(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", CANARIO)
    monkeypatch.setattr(h2a.procesos, "leer_entorno", lambda pid, v: {})
    monkeypatch.setattr(h2a.procesos, "entorno_legible", lambda pid: True)
    h = ejecutar(servidor(pid=5))
    assert "GROQ_API_KEY" not in repr(h) and CANARIO not in repr(h)


def test_env_sin_proceso_local():
    assert "no hay un proceso local" in uno(ejecutar(servidor(pid=None)), "H2-ENV").evidencia
