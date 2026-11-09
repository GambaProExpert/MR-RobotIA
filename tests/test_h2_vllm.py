"""Pruebas del perfil de vLLM: sondeo solo con GET, arranque y los invariantes de punta a punta.

El servidor falso sigue lo que dicta el código de vLLM 0.33.0: ninguna de estas pruebas se ha
contrastado con un vLLM real.
"""
import json
import sys
import types
from pathlib import Path

import pytest

from mrrobotia import cli
from mrrobotia.contexto import Contexto, ServidorDetectado
from mrrobotia.modulos import h2_identificacion as h2id
from mrrobotia.modulos import h3_puertos as h3
from mrrobotia.modulos.h2_arranque import FILA_A_OBSERVADO, H2Arranque
from mrrobotia.nucleo import Severidad
from mrrobotia.perfiles import PERFILES
from mrrobotia.perfiles import vllm as perfil_vllm
from mrrobotia.perfiles.vllm import RUTAS_CONTROL, RUTAS_INFERENCIA
from mrrobotia.procesos import Proceso
from mrrobotia.red import ClienteHTTP
from servidor_falso import SOLO_POST_DESARROLLO, ServidorFalso, desde_rutas, vllm

VLLM = PERFILES[1]
CANARIO_CLAVE = "canario-clave-no-debe-salir"
CANARIO_TOKEN = "canario-hf-no-debe-salir"
CANARIO_TEXTO = "canario-plantilla-no-debe-salir"
CANARIO_KV = "tcp://10.99.99.99:5557"
RUTA_PRIVADA = "/srv/ruta-canario/modelos/qwen"

# Rutas que actúan con un POST (vacío o no): `vllm.md` §2.4. Nunca reciben uno.
NUNCA_POST = {"/pause", "/resume", "/sleep", "/wake_up", "/release_kv_cache_memory", "/reset_prefix_cache", "/reset_mm_cache",
              "/reset_encoder_cache", "/start_profile", "/stop_profile", "/shutdown_weight_transfer_engine", "/start_weight_update",
              "/start_draft_weight_update", "/finish_weight_update", "/abort_requests", "/collective_rpc", "/scale_elastic_ep",
              "/fault_tolerance/apply", "/init_weight_transfer_engine", "/update_weights", "/update_weight_version", "/weight_checker",
              "/tokenize", "/detokenize", "/v1/chat/completions"}
# Rutas que el sondeo puede pedir. Cualquier otra, incluida `/server_info`, hace fallar la prueba.
RUTAS_DEL_SONDEO = {"/v1/models", "/version", "/metrics", "/load", "/kv_event_sources", "/tokenizer_info", "/openapi.json",
                    perfil_vllm.RUTA_DESARROLLO, *RUTAS_INFERENCIA, *RUTAS_CONTROL}


def servidor(**kw):
    return ServidorDetectado(**{"tipo": "vllm", "host": "127.0.0.1", "puerto": 1, "fuentes": ["http"], "enlace": "loopback", **kw})


def ids(hallazgos):
    return [h.id for h in hallazgos]


def uno(hallazgos, id_):
    id_ = id_ if id_.startswith("H2-") else f"H2-ARRANQUE-{id_}"
    encontrados = [h for h in hallazgos if h.id == id_]
    assert len(encontrados) == 1, ids(hallazgos)
    return encontrados[0]


def sondear(responder, s=None, expuesto=False, proxy=False):
    s = s or servidor()
    with ServidorFalso(responder) as falso:
        hallazgos = VLLM.sondear(ClienteHTTP(falso.url, timeout=2), s, expuesto, proxy)
    return hallazgos, falso.rutas(), s


# ------------------------------------------------------------ comunes
def test_sin_clave():
    h, rutas, s = sondear(vllm())
    assert uno(h, "H2-AUTH").severidad == Severidad.MEDIA and s.autenticacion == "abierta" and "GET /v1/models" in uno(h, "H2-AUTH").evidencia
    assert uno(h, "H2-BUILD").evidencia == "versión = 0.33.0; /version la publica sin clave" and s.version == "0.33.0"
    assert uno(h, "H2-MODELS").severidad == Severidad.BAJA
    assert {m for m, _ in rutas} == {"GET"}


def test_con_clave():
    h, _, s = sondear(vllm(clave="k"))
    assert uno(h, "H2-AUTH").severidad == Severidad.INFO and s.autenticacion == "activa" and "H2-MODELS" not in ids(h)


def test_autenticacion_tras_proxy_no_concluye_ni_borra_lo_del_arranque():
    def responder(p):
        return (403, {"Server": "nginx"}, b'{"detail":"prohibido"}') if p.ruta == "/v1/models" else vllm()(p)

    h, _, s = sondear(responder, servidor(autenticacion="activa"))
    aut = uno(h, "H2-AUTH")
    assert aut.estado == "sin_concluir" and "proxy" in aut.evidencia and "el arranque configura una clave" in aut.evidencia
    assert s.autenticacion == "activa"


def test_ruta_absoluta_en_root_es_media_y_no_se_vuelca():
    h, _, _ = sondear(vllm(raiz=RUTA_PRIVADA))
    assert uno(h, "H2-MODELS").severidad == Severidad.MEDIA and "ruta-canario" not in repr(h)


def test_identificador_de_hugging_face_no_es_ruta():
    assert uno(sondear(vllm(modelo="Qwen/Qwen2.5-7B"))[0], "H2-MODELS").severidad == Severidad.BAJA


@pytest.mark.parametrize("expuesto,severidad", [(False, Severidad.BAJA), (True, Severidad.MEDIA)])
def test_metricas_solo_el_numero_de_series(expuesto, severidad):
    h, _, _ = sondear(vllm(), expuesto=expuesto)
    metricas = uno(h, "H2-METRICS")
    assert metricas.severidad == severidad and "2 serie(s)" in metricas.evidencia and "model_name" not in metricas.evidencia


def test_metricas_no_se_piden_sin_la_forma_de_vllm():
    def responder(p):
        return (200, {}, b'{"otra":"cosa"}') if p.ruta == "/version" else vllm()(p)

    _, rutas, _ = sondear(responder)
    assert ("GET", "/metrics") not in rutas


# ------------------------------------------------------------ control y rutas
def test_con_proxy_o_comodin_no_se_concluye_por_rutas():
    h, rutas, _ = sondear(vllm(comodin=True, desarrollo=True, clave="k"), expuesto=True)
    r = uno(h, "H2-RUTAS")
    assert r.estado == "sin_concluir" and "200" in r.evidencia
    assert not {"H2-DESARROLLO", "H2-INFERENCIA-SIN-CLAVE", "H2-CONTROL-SIN-CLAVE", "H2-OPENAPI", "H2-LOAD",
                "H2-KV-EVENTS", "H2-TOKENIZER-INFO"} & set(ids(h))
    assert ("GET", perfil_vllm.RUTA_DESARROLLO) not in rutas


def test_el_control_va_antes_de_interpretar_las_rutas():
    _, rutas, _ = sondear(vllm())
    control = next(i for i, (_, r) in enumerate(rutas) if r.startswith("/mrrobotia-"))
    assert control < rutas.index(("GET", perfil_vllm.RUTA_DESARROLLO))


@pytest.mark.parametrize("expuesto,severidad", [(False, Severidad.ALTA), (True, Severidad.CRITICA)])
def test_modo_desarrollo(expuesto, severidad):
    h, rutas, _ = sondear(vllm(desarrollo=True), expuesto=expuesto)
    d = uno(h, "H2-DESARROLLO")
    assert d.severidad == severidad and "/collective_rpc" in d.evidencia and d.estado == "confirmado"
    assert ("POST", perfil_vllm.RUTA_DESARROLLO) not in rutas


def test_modo_desarrollo_inactivo():
    d = uno(sondear(vllm())[0], "H2-DESARROLLO")
    assert d.severidad == Severidad.INFO and "inactivo" in d.titulo


def test_modo_desarrollo_sin_concluir():
    def responder(p):
        return (500, {}, b"") if p.ruta == perfil_vllm.RUTA_DESARROLLO else vllm()(p)

    assert uno(sondear(responder)[0], "H2-DESARROLLO").estado == "sin_concluir"


# ---------------------------------------------------------- inferencia sin clave
@pytest.mark.parametrize("expuesto,proxy,severidad", [
    (False, False, Severidad.BAJA), (True, False, Severidad.CRITICA), (True, True, Severidad.MEDIA), (False, True, Severidad.BAJA),
])
def test_inferencia_abierta_con_clave(expuesto, proxy, severidad):
    h, _, _ = sondear(vllm(clave="k"), expuesto=expuesto, proxy=proxy)
    i = uno(h, "H2-INFERENCIA-SIN-CLAVE")
    assert i.severidad == severidad and "/invocations" in i.evidencia and "/generative_scoring" in i.evidencia and i.estado == "confirmado"


def test_inferencia_agrupa_las_rutas_de_pooling():
    assert "/rerank" in uno(sondear(vllm(clave="k", pooling=True))[0], "H2-INFERENCIA-SIN-CLAVE").evidencia


def test_sin_clave_la_inferencia_abierta_no_es_otra_causa():
    assert "H2-INFERENCIA-SIN-CLAVE" not in ids(sondear(vllm())[0])


# --------------------------------------------------------------- controles
@pytest.mark.parametrize("arranque,ruta", [({"tokens_only": True}, "/abort_requests"), ({"perfilador": True}, "/start_profile"),
                                           ({"tolerancia": True}, "/fault_tolerance/apply")])
def test_controles_sin_clave_agrupados(arranque, ruta):
    c = uno(sondear(vllm(**arranque))[0], "H2-CONTROL-SIN-CLAVE")
    assert ruta in c.evidencia and "/scale_elastic_ep" in c.evidencia


@pytest.mark.parametrize("expuesto,severidad", [(False, Severidad.BAJA), (True, Severidad.ALTA)])
def test_severidad_de_los_controles(expuesto, severidad):
    assert uno(sondear(vllm(), expuesto=expuesto)[0], "H2-CONTROL-SIN-CLAVE").severidad == severidad


def test_abort_requests_de_desarrollo_no_es_otra_causa():
    assert "/abort_requests" not in uno(sondear(vllm(desarrollo=True))[0], "H2-CONTROL-SIN-CLAVE").evidencia


# ---------------------------------------------------- documentación e información
@pytest.mark.parametrize("expuesto,severidad", [(False, Severidad.BAJA), (True, Severidad.MEDIA)])
def test_openapi_solo_cuantas_rutas(expuesto, severidad):
    o = uno(sondear(vllm(), expuesto=expuesto)[0], "H2-OPENAPI")
    assert o.severidad == severidad and "3 ruta(s)" in o.evidencia and "/tokenize" not in o.evidencia


def test_openapi_desactivada():
    assert "H2-OPENAPI" not in ids(sondear(vllm(docs=False))[0])


@pytest.mark.parametrize("expuesto,severidad", [(False, Severidad.INFO), (True, Severidad.BAJA)])
def test_load_sin_contenido(expuesto, severidad):
    carga = uno(sondear(vllm(), expuesto=expuesto)[0], "H2-LOAD")
    assert carga.severidad == severidad and "server_load" not in carga.evidencia and "3" not in carga.evidencia.split("(")[0]


def test_kv_events_vacio_no_es_hallazgo():
    assert "H2-KV-EVENTS" not in ids(sondear(vllm())[0])


def test_kv_events_no_vuelca_direcciones():
    h, _, _ = sondear(vllm(eventos_kv={"0": [CANARIO_KV], "1": [CANARIO_KV]}))
    assert "2 entrada(s)" in uno(h, "H2-KV-EVENTS").evidencia and CANARIO_KV not in repr(h)


def test_tokenizer_info_no_vuelca_plantillas():
    h, _, _ = sondear(vllm(tokenizador=CANARIO_TEXTO), expuesto=True)
    assert uno(h, "H2-TOKENIZER-INFO").severidad == Severidad.MEDIA and CANARIO_TEXTO not in repr(h)
    assert "H2-TOKENIZER-INFO" not in ids(sondear(vllm())[0])


def test_solo_pide_las_rutas_previstas():
    _, rutas, _ = sondear(vllm(desarrollo=True, pooling=True, tokens_only=True, perfilador=True, tolerancia=True, tokenizador="x", clave="k"))
    pedidas = {r for _, r in rutas if not r.startswith("/mrrobotia-")}
    assert pedidas <= RUTAS_DEL_SONDEO and "/server_info" not in pedidas


def test_sin_post_permitidos():
    assert VLLM.post_permitidos == frozenset()


def test_un_host_manipulado_nunca_se_envia():
    with ServidorFalso(vllm(version="0.20.0", clave="k")) as falso:
        VLLM.sondear(ClienteHTTP(falso.url, timeout=2), servidor(), False, False)
    assert all("?" not in p.cabeceras.get("host", "") for p in falso.peticiones)


# ---------------------------------------------------------------- arranque
def evaluar(opciones=None, entorno=None, expuesto=False, autenticacion="activa", **kw):
    s = servidor(opciones=opciones or {}, entorno=entorno or {}, autenticacion=autenticacion, **kw)
    return VLLM.evaluar_arranque(s, expuesto)


@pytest.mark.parametrize("opciones,entorno,fila,loopback,en_red", [
    ({"trust_remote_code": True}, {}, "TRUST-REMOTE-CODE", Severidad.ALTA, Severidad.ALTA),
    ({"allowed_local_media_path": "m"}, {}, "MEDIA-PATH", Severidad.MEDIA, Severidad.ALTA),
    ({"enable_tokenizer_info_endpoint": True}, {}, "TOKENIZER-INFO", Severidad.BAJA, Severidad.MEDIA),
    ({"enable_log_outputs": True}, {}, "LOG-SALIDAS", Severidad.MEDIA, Severidad.MEDIA),
    ({"enable_server_load_tracking": True}, {}, "LOAD", Severidad.INFO, Severidad.BAJA),
    ({"trust_request_chat_template": True}, {}, "CHAT-TEMPLATE-CLIENTE", Severidad.BAJA, Severidad.MEDIA),
    ({"trust_request_mm_kwargs": True}, {}, "MM-KWARGS-CLIENTE", Severidad.BAJA, Severidad.MEDIA),
    ({"tokens_only": True}, {}, "TOKENS-ONLY", Severidad.BAJA, Severidad.ALTA),
    ({"enable_scale_out": True}, {}, "SCALE-OUT", Severidad.BAJA, Severidad.MEDIA),
    ({"profiler_config": True}, {}, "PROFILER", Severidad.BAJA, Severidad.ALTA),
    ({"enable_fault_tolerance": True}, {}, "FAULT-TOLERANCE", Severidad.BAJA, Severidad.ALTA),
    ({"grpc": True}, {}, "GRPC", Severidad.MEDIA, Severidad.ALTA),
    ({"grpc_port": "9"}, {}, "GRPC", Severidad.MEDIA, Severidad.ALTA),
    ({"hf_token": True}, {}, "HF-TOKEN", Severidad.MEDIA, Severidad.MEDIA),
    ({"tool_server": "demo"}, {}, "TOOLS", Severidad.MEDIA, Severidad.ALTA),
    ({}, {"VLLM_SERVER_DEV_MODE": "1"}, "DESARROLLO", Severidad.ALTA, Severidad.CRITICA),
    ({}, {"VLLM_ALLOW_RUNTIME_LORA_UPDATING": "1"}, "LORA-DINAMICO", Severidad.MEDIA, Severidad.ALTA),
    ({}, {"VLLM_ALLOW_INSECURE_SERIALIZATION": "1"}, "SERIALIZACION-INSEGURA", Severidad.ALTA, Severidad.ALTA),
    ({}, {"VLLM_DEBUG_LOG_API_SERVER_RESPONSE": "1"}, "LOG-RESPUESTAS", Severidad.MEDIA, Severidad.ALTA),
    ({}, {"VLLM_GPT_OSS_SYSTEM_TOOL_MCP_LABELS": "a"}, "MCP", Severidad.BAJA, Severidad.MEDIA),
    ({}, {"VLLM_ENABLE_RESPONSES_API_STORE": "1"}, "RESPUESTAS-GUARDADAS", Severidad.BAJA, Severidad.MEDIA),
    ({}, {"VLLM_MEDIA_URL_ALLOW_REDIRECTS": "1"}, "MEDIA-REDIRECCIONES", Severidad.INFO, Severidad.BAJA),
    ({}, {"VLLM_MAX_N_SEQUENCES": "100"}, "MAX-SEQUENCES", Severidad.INFO, Severidad.BAJA),
])
def test_severidades(opciones, entorno, fila, loopback, en_red):
    assert uno(evaluar(opciones, entorno), fila).severidad == loopback
    assert uno(evaluar(opciones, entorno, expuesto=True), fila).severidad == en_red


@pytest.mark.parametrize("opciones,entorno,fila", [
    ({"trust_remote_code": False}, {}, "TRUST-REMOTE-CODE"), ({}, {"VLLM_SERVER_DEV_MODE": "0"}, "DESARROLLO"),
    ({}, {"VLLM_ENABLE_RESPONSES_API_STORE": "false"}, "RESPUESTAS-GUARDADAS"),
])
def test_desactivadas_no_cuentan(opciones, entorno, fila):
    assert f"H2-ARRANQUE-{fila}" not in ids(evaluar(opciones, entorno))


def test_lora_dinamico_solo_por_su_efecto_documentado():
    h = uno(evaluar(entorno={"VLLM_ALLOW_RUNTIME_LORA_UPDATING": "1"}), "LORA-DINAMICO")
    assert "cargar y descargar adaptadores" in h.titulo


def test_host_por_defecto_es_potencial_y_alta():
    h = uno(evaluar(), "HOST")
    assert (h.severidad, h.estado) == (Severidad.ALTA, "potencial") and "todas las interfaces" in h.evidencia


def test_host_fuera_de_loopback():
    h = uno(evaluar({"host": "0.0.0.0"}, autenticacion="abierta"), "HOST")
    assert (h.severidad, h.estado) == (Severidad.ALTA, "confirmado")


@pytest.mark.parametrize("opciones", [{"host": "127.0.0.1"}, {"uds": "a.sock"}])
def test_host_en_loopback_o_socket(opciones):
    assert "H2-ARRANQUE-HOST" not in ids(evaluar(opciones))


def test_clave_en_la_linea_de_ordenes():
    assert uno(evaluar({"api_key": True}), "CLAVE-EN-ORDEN").severidad == Severidad.MEDIA


def test_clave_por_entorno_no_es_llamada_de_atencion():
    assert "H2-ARRANQUE-CLAVE-EN-ORDEN" not in ids(evaluar(entorno={"VLLM_API_KEY": True}))


def test_frontend_rust_puede_llevar_la_clave_en_args_json():
    h = uno(evaluar({"args_json": True}), "CLAVE-EN-ORDEN")
    assert h.estado == "potencial" and "--args-json" in h.evidencia


@pytest.mark.parametrize("expuesto,severidad", [(False, Severidad.BAJA), (True, Severidad.CRITICA)])
def test_sin_clave_segun_exposicion(expuesto, severidad):
    assert uno(evaluar(expuesto=expuesto, autenticacion="abierta"), "SIN-CLAVE").severidad == severidad


@pytest.mark.parametrize("autenticacion,estado", [("abierta", "confirmado"), (None, "potencial"), ("indeterminada", "potencial")])
def test_sin_clave_estado(autenticacion, estado):
    assert uno(evaluar(autenticacion=autenticacion), "SIN-CLAVE").estado == estado


def test_tls():
    assert uno(evaluar(), "TLS").severidad == Severidad.BAJA and uno(evaluar(expuesto=True), "TLS").severidad == Severidad.ALTA
    assert "H2-ARRANQUE-TLS" not in ids(evaluar({"ssl_certfile": "c.pem"}))


@pytest.mark.parametrize("valor", ['["*"]', "*", '["*","https://a.test"]'])
def test_cors_comodin(valor):
    h = uno(evaluar({"allowed_origins": valor}), "CORS")
    assert h.severidad == Severidad.BAJA and h.estado == "confirmado" and "allowed_origins=*" in h.evidencia
    assert uno(evaluar({"allowed_origins": valor}, expuesto=True), "CORS").severidad == Severidad.MEDIA


def test_cors_con_credenciales():
    assert "credenciales=sí" in uno(evaluar({"allowed_origins": '["*"]', "allow_credentials": True}), "CORS").evidencia


def test_cors_restringido_no_es_hallazgo():
    assert "H2-ARRANQUE-CORS" not in ids(evaluar({"allowed_origins": '["https://app.test"]'}))


@pytest.mark.parametrize("version,hay", [("0.31.0", True), ("0.32.0", False), ("0.33.0", False), (None, False), ("dev", False)])
def test_cors_por_defecto_segun_version(version, hay):
    h = evaluar(version=version)
    assert ("H2-ARRANQUE-CORS" in ids(h)) is hay
    if hay:
        assert uno(h, "CORS").estado == "potencial"


def test_documentacion():
    assert uno(evaluar(), "OPENAPI").estado == "potencial" and uno(evaluar(expuesto=True), "OPENAPI").severidad == Severidad.MEDIA
    assert "H2-ARRANQUE-OPENAPI" not in ids(evaluar({"disable_fastapi_docs": True}))


def test_dominios_de_medios():
    assert uno(evaluar(), "MEDIA-DOMINIOS").estado == "potencial"
    assert "H2-ARRANQUE-MEDIA-DOMINIOS" not in ids(evaluar({"allowed_media_domains": "a.test"}))


@pytest.mark.parametrize("nivel,severidad", [("", Severidad.MEDIA), ("DEBUG", Severidad.ALTA)])
def test_registro_de_peticiones(nivel, severidad):
    entorno = {"VLLM_LOGGING_LEVEL": nivel} if nivel else {}
    assert uno(evaluar({"enable_log_requests": True}, entorno), "LOG-PROMPTS").severidad == severidad


def test_servidor_de_herramientas_propio_no_es_demo():
    assert "H2-ARRANQUE-TOOLS" not in ids(evaluar({"tool_server": "host:9"}))


def test_huella():
    assert uno(evaluar(), "FINGERPRINT").severidad == Severidad.INFO and uno(evaluar(expuesto=True), "FINGERPRINT").severidad == Severidad.BAJA
    assert "H2-ARRANQUE-FINGERPRINT" not in ids(evaluar({"fingerprint_mode": "none"}))


def test_telemetria_con_entorno_legible():
    h = uno(evaluar(entorno={"VLLM_LOGGING_LEVEL": "INFO"}), "TELEMETRIA")
    assert (h.severidad, h.estado) == (Severidad.BAJA, "confirmado") and "DO_NOT_TRACK" in h.evidencia


@pytest.mark.parametrize("variable", ["VLLM_NO_USAGE_STATS", "VLLM_DO_NOT_TRACK", "DO_NOT_TRACK"])
def test_telemetria_desactivada(variable):
    assert "H2-ARRANQUE-TELEMETRIA" not in ids(evaluar(entorno={variable: "1"}))


def test_telemetria_sin_entorno_legible_no_afirma(monkeypatch):
    monkeypatch.setattr(perfil_vllm.procesos, "entorno_legible", lambda pid: False)
    h = uno(evaluar(pid=5), "TELEMETRIA")
    assert h.estado == "potencial" and "no es legible" in h.evidencia and "envía" not in h.titulo


def test_telemetria_sin_proceso_no_afirma():
    assert uno(evaluar(pid=None), "TELEMETRIA").estado == "potencial"


def test_telemetria_con_entorno_vacio_pero_legible(monkeypatch):
    monkeypatch.setattr(perfil_vllm.procesos, "entorno_legible", lambda pid: True)
    assert uno(evaluar(pid=5), "TELEMETRIA").estado == "confirmado"


def test_inventario_en_un_unico_hallazgo():
    h = uno(evaluar({"port": "9", "enable_offline_docs": True, "middleware": "m"}, {"VLLM_PLUGINS": "secreto-de-valor"}), "OTRAS")
    assert h.severidad == Severidad.INFO and "port=9" in h.evidencia and "enable_offline_docs=presente" in h.evidencia
    assert "VLLM_PLUGINS" in h.evidencia and "secreto-de-valor" not in h.evidencia


def test_fichero_de_configuracion_lo_avisa():
    assert uno(evaluar({"config": "a.yaml"}), "CONFIG").estado == "sin_concluir"


def test_el_prefijo_de_la_api_no_genera_ninguna_fila():
    assert set(ids(evaluar({"model": "m", "root_path": "/api"}))) == set(ids(evaluar({"model": "m"})))


def test_sin_valores_de_secretos():
    opciones = VLLM.analizar_argv(["vllm", "serve", "m", "--api-key", CANARIO_CLAVE, "--hf-token", CANARIO_TOKEN,
                                   "--args-json", f'{{"api_key":["{CANARIO_CLAVE}"]}}', "--profiler-config", CANARIO_TOKEN])
    hallazgos = VLLM.evaluar_arranque(servidor(opciones=opciones), True)
    assert CANARIO_CLAVE not in repr(hallazgos) and CANARIO_TOKEN not in repr(hallazgos)


def test_identificadores_compartidos_con_llamacpp():
    filas = {h.id for h in evaluar({"api_key": True, "hf_token": True, "allowed_origins": '["*"]', "host": "0.0.0.0"})}
    assert {"H2-ARRANQUE-HOST", "H2-ARRANQUE-CLAVE-EN-ORDEN", "H2-ARRANQUE-CORS", "H2-ARRANQUE-TLS", "H2-ARRANQUE-HF-TOKEN"} <= filas


def test_lo_observado_manda_sobre_el_arranque():
    s = servidor(opciones={"model": "m"}, entorno={"VLLM_SERVER_DEV_MODE": "1"}, autenticacion="abierta", observado=sorted(set(FILA_A_OBSERVADO.values())))
    m = H2Arranque()
    m.contexto = Contexto("linux", servidores=[s])
    h = {x.id for x in m.ejecutar({})}
    assert not {"H2-ARRANQUE-SIN-CLAVE", "H2-ARRANQUE-DESARROLLO", "H2-ARRANQUE-OPENAPI", "H2-ARRANQUE-TLS", "H2-ARRANQUE-HOST"} & h
    assert "H2-ARRANQUE-TELEMETRIA" in h


# ------------------------------------------------------------ puertos del perfil
def test_puertos_internos():
    assert {5557, 5600, 8998, 9256, 14579, 29500, 29501, 29550, 8265, 10001} == set(VLLM.puertos_internos)
    assert all(isinstance(descripcion, str) and descripcion for descripcion in VLLM.puertos_internos.values())


# --------------------------------------------------------- de punta a punta
@pytest.fixture
def entorno(monkeypatch):
    e = types.SimpleNamespace(procesos=[], abiertos=set())
    monkeypatch.setattr(h2id.procesos, "enumerar", lambda: list(e.procesos))
    monkeypatch.setattr(h2id.red, "tabla_puertos", lambda: "")
    monkeypatch.setattr(h3, "tabla_puertos", lambda: "")
    monkeypatch.setattr(h3, "ip_rutable", lambda: None)         # sin IP de red, el barrido no conecta con nada
    monkeypatch.setattr(h2id.red, "sondear", lambda host, puerto, timeout=2: puerto in e.abiertos)
    monkeypatch.setattr(h2id.red, "ip_rutable", lambda: None)
    monkeypatch.setattr(h2id.red, "owner_proceso", lambda pid, timeout=10: None)
    return e


def _auditar(entorno, monkeypatch, tmp_path, responder, *argv):
    with ServidorFalso(responder) as s:
        if argv:
            entorno.procesos = [Proceso(100, "python", ["/opt/ruta-canario/bin/python", "/opt/ruta-canario/bin/vllm", "serve", RUTA_PRIVADA,
                                                        "--port", str(s.puerto), "--host", "127.0.0.1", *argv])]
        entorno.abiertos = {s.puerto}
        objetivo = {"nombre": "x", "host": "127.0.0.1", "endpoint": s.url, "permitir_activos": True,
                    "autorizacion": {"tengo_autorizacion": True, "autorizado_por": "x", "ambito": "x", "fecha": "2026-01-01"}}
        ruta = tmp_path / "objetivo.json"
        ruta.write_text(json.dumps(objetivo), encoding="utf-8")
        salida = tmp_path / "informe"
        monkeypatch.setattr(sys, "argv", ["mrrobotia", "--objetivo", str(ruta), "--salida", str(salida), "--permitir-activos",
                                          "--escaneo", "exposicion,arranque,cve,puertos"])
        cli.main()
    informe = Path(str(salida) + ".json").read_text(encoding="utf-8") + Path(str(salida) + ".md").read_text(encoding="utf-8")
    return s.peticiones, informe


ESCENARIOS = {
    "sin-clave": {}, "con-clave": {"clave": "k"}, "desarrollo": {"desarrollo": True},
    "desarrollo-con-clave": {"desarrollo": True, "clave": "k"},
    "completo": {"desarrollo": True, "pooling": True, "tokens_only": True, "perfilador": True, "tolerancia": True, "tokenizador": "t",
                 "eventos_kv": {"0": ["x"]}, "clave": "k"},
}


@pytest.mark.parametrize("escenario", ESCENARIOS.values(), ids=ESCENARIOS.keys())
def test_invariante_solo_peticiones_sin_efectos(entorno, monkeypatch, tmp_path, escenario):
    peticiones, _ = _auditar(entorno, monkeypatch, tmp_path, vllm(**escenario))
    assert peticiones
    for p in peticiones:
        assert p.metodo in {"GET", "HEAD", "OPTIONS"}, (p.metodo, p.ruta)
        assert p.cuerpo == b"", (p.metodo, p.ruta)


def test_ninguna_ruta_que_actua_recibe_un_post(entorno, monkeypatch, tmp_path):
    peticiones, _ = _auditar(entorno, monkeypatch, tmp_path, vllm(**ESCENARIOS["completo"]))
    assert not [p for p in peticiones if p.metodo == "POST"]
    assert not [p for p in peticiones if p.ruta in NUNCA_POST and p.metodo not in {"GET", "HEAD", "OPTIONS"}]
    assert not SOLO_POST_DESARROLLO - NUNCA_POST            # la tabla del servidor falso está cubierta


def test_nunca_se_pide_server_info(entorno, monkeypatch, tmp_path):
    peticiones, _ = _auditar(entorno, monkeypatch, tmp_path, vllm(**ESCENARIOS["completo"]))
    assert not [p for p in peticiones if p.ruta.partition("?")[0] == "/server_info"]


def test_invariante_canarios(entorno, monkeypatch, tmp_path):
    respuesta = vllm(clave=CANARIO_CLAVE, desarrollo=True, tokenizador=CANARIO_TEXTO, eventos_kv={"0": [CANARIO_KV]}, raiz=RUTA_PRIVADA)
    peticiones, informe = _auditar(entorno, monkeypatch, tmp_path, respuesta, "--api-key", CANARIO_CLAVE, "--hf-token", CANARIO_TOKEN)
    assert peticiones and "H2-ARRANQUE-CLAVE-EN-ORDEN" in informe and "H2-ARRANQUE-HF-TOKEN" in informe
    for canario in (CANARIO_CLAVE, CANARIO_TOKEN, CANARIO_TEXTO, CANARIO_KV, "ruta-canario"):
        assert canario not in informe


def test_una_causa_un_hallazgo(entorno, monkeypatch, tmp_path):
    _, informe = _auditar(entorno, monkeypatch, tmp_path, vllm(desarrollo=True), "--trust-remote-code")
    assert "H2-AUTH" in informe and "H2-DESARROLLO" in informe and "H2-ARRANQUE-TRUST-REMOTE-CODE" in informe
    for fila in ("SIN-CLAVE", "TLS", "OPENAPI"):
        assert f"H2-ARRANQUE-{fila}" not in informe


def test_cve_en_el_informe(entorno, monkeypatch, tmp_path):
    _, informe = _auditar(entorno, monkeypatch, tmp_path, vllm(version="0.32.0"))
    assert "H2-CVE-ALTA" in informe and "GHSA-q9v9-qpjp-fc24" in informe


def test_la_sonda_de_control_es_distinta_cada_vez():
    respuestas = {"GET /version": (200, {"Server": "uvicorn"}, b'{"version":"0.33.0"}')}
    rutas = [next(r for _, r in sondear(desde_rutas(respuestas))[1] if r.startswith("/mrrobotia-")) for _ in range(2)]
    assert rutas[0] != rutas[1]


def test_server_info_esta_vetada_en_el_cliente():
    with ServidorFalso(vllm(desarrollo=True)) as falso:
        respuesta = ClienteHTTP(falso.url, timeout=2).get("/server_info?config_format=json")
    assert respuesta.error == "ruta vetada" and falso.peticiones == []


def test_el_inventario_no_repite_el_servidor_de_demostracion():
    assert "tool_server" not in uno(evaluar({"tool_server": "demo", "port": "9"}), "OTRAS").evidencia
