"""Pruebas de los perfiles: análisis de la línea de órdenes (lista blanca y secretos),
reconocimiento de procesos e identificación por HTTP contra servidores falsos."""
import re

import pytest

from mrrobotia.contexto import ServidorDetectado
from mrrobotia.perfiles import GENERICO, PERFILES, perfil_de, por_id
from mrrobotia.perfiles.base import nombre_fichero, nombre_modelo, normalizar_prefijo, version_segura
from mrrobotia.red import ClienteHTTP
from servidor_falso import (
    BUILD_LLAMACPP, RUTA_MODELO_FALSA, ServidorFalso, desde_rutas, generico_openai, http_simple,
    llamacpp, vllm,
)

LLAMA, VLLM = PERFILES
CANARIO = "canario-no-debe-salir"


def identificar(perfil, responder, prefijo=""):
    with ServidorFalso(responder) as s:
        ident = perfil.identificar_http(ClienteHTTP(s.url + prefijo, timeout=2))
    return ident, s.rutas()


# ------------------------------------------------------------ auxiliares de saneado
@pytest.mark.parametrize("ruta,esperado", [
    (r"C:\modelos\a.gguf", "a.gguf"), ("/srv/modelos/a.gguf", "a.gguf"), ("a.gguf", "a.gguf"),
    (r"\\servidor\recurso\a.gguf", "a.gguf"), ("/srv/modelos/", "modelos"), ("", ""),
])
def test_nombre_fichero(ruta, esperado):
    assert nombre_fichero(ruta) == esperado


@pytest.mark.parametrize("valor,esperado", [
    (r"F:\privado\a.gguf", "a.gguf"), ("/privado/modelos/a.gguf", "a.gguf"), ("~/a.gguf", "a.gguf"),
    ("./a.gguf", "a.gguf"), ("modelos/a.gguf", "a.gguf"),
    ("Qwen/Qwen2.5-7B", "Qwen/Qwen2.5-7B"), ("alias-corto", "alias-corto"),
    ("none", None), ("", None), (None, None), (True, None),
])
def test_nombre_modelo(valor, esperado):
    assert nombre_modelo(valor) == esperado


def test_nombre_modelo_quita_marcado():
    assert "|" not in nombre_modelo("ali|as\n[x](http://y)")


@pytest.mark.parametrize("valor,esperado", [
    ("b11583-988015788", "b11583-988015788"), ("0.33.0+cpu", "0.33.0+cpu"), ("0.33.0rc1.dev4", "0.33.0rc1.dev4"),
    ("[x](http://malo)", None), ("a" * 80, None), (None, None), (5, None),
])
def test_version_segura(valor, esperado):
    assert version_segura(valor) == esperado


@pytest.mark.parametrize("valor,esperado", [("/lab", "/lab"), ("lab/", "/lab"), ("/", ""), ("", ""), (True, ""), (None, "")])
def test_normalizar_prefijo(valor, esperado):
    assert normalizar_prefijo(valor) == esperado


# ------------------------------------------------------------- argv de llama.cpp
def test_llamacpp_opciones_saneadas():
    argv = [r"C:\srv\llama-server.exe", "-m", r"F:\privado\modelo.gguf", "--host", "0.0.0.0", "--port", "8080",
            "--api-key", CANARIO, "--no-webui", "-c", "256", "--metrics", "--slot-save-path", "/var/guardado/slots",
            "--hf-token", CANARIO, "-mu", f"https://u:{CANARIO}@h/m.gguf", "--mcp-servers-json", f'{{"k":"{CANARIO}"}}']
    opciones = LLAMA.analizar_argv(argv)
    assert opciones == {
        "model": "modelo.gguf", "host": "0.0.0.0", "port": "8080", "api_key": True, "webui": False, "ctx_size": "256",
        "metrics": True, "slot_save_path": "slots", "hf_token": True, "model_url": True, "mcp_servers_json": True,
    }
    assert CANARIO not in repr(opciones)


def test_llamacpp_lo_que_no_esta_en_la_tabla_no_se_guarda():
    opciones = LLAMA.analizar_argv(["llama-server", "--inventada", CANARIO, "-ngl", "99", CANARIO, "--port", "1"])
    assert opciones == {"port": "1"}


def test_guion_bajo_equivale_a_guion():
    assert LLAMA.analizar_argv(["llama-server", "--api_key", CANARIO, "--slot_save_path", "/a/b"]) == {
        "api_key": True, "slot_save_path": "b"}


def test_forma_con_igual_no_filtra_secretos():
    assert LLAMA.analizar_argv(["llama-server", f"--api-key={CANARIO}", "--port=9"]) == {"api_key": True, "port": "9"}


def test_valor_negativo_es_un_valor():
    assert LLAMA.analizar_argv(["llama-server", "--sleep-idle-seconds", "-1", "--port", "5"]) == {
        "sleep_idle_seconds": "-1", "port": "5"}


def test_una_opcion_no_se_traga_a_la_siguiente():
    # Si --alias tomara «--api-key» como valor, el secreto quedaría sin reconocer.
    opciones = LLAMA.analizar_argv(["llama-server", "--alias", "--api-key", CANARIO])
    assert opciones == {"api_key": True}


def test_opcion_final_sin_valor():
    assert LLAMA.analizar_argv(["llama-server", "--port"]) == {}
    assert LLAMA.analizar_argv(["llama-server", "--api-key"]) == {"api_key": True}


def test_url_con_credenciales_en_opcion_no_secreta():
    assert VLLM.analizar_argv(["vllm", "serve", "m", "--tool-server", f"http://u:{CANARIO}@h:1"])["tool_server"] is True


def test_argv_vacio():
    assert LLAMA.analizar_argv([]) == {} and LLAMA.analizar_argv(None) == {}


def test_socket_unix_solo_guarda_el_nombre():
    assert LLAMA.analizar_argv(["llama-server", "--host", "/var/run/privado/llama.sock"]) == {"host": "llama.sock"}


# ----------------------------------------------------------------- argv de vLLM
def test_vllm_forma_serve():
    argv = ["/v/bin/python", "/v/bin/vllm", "serve", "Qwen/Qwen2.5-7B", "--host=0.0.0.0", "--api-key", CANARIO, "otra-clave",
            "--trust-remote-code", "--no-enable-log-requests", "--allowed-origins", '["*"]']
    opciones = VLLM.analizar_argv(argv)
    assert opciones == {"model": "Qwen/Qwen2.5-7B", "host": "0.0.0.0", "api_key": True, "trust_remote_code": True,
                        "enable_log_requests": False, "allowed_origins": '["*"]'}
    assert CANARIO not in repr(opciones) and "otra-clave" not in repr(opciones)


def test_vllm_modelo_por_opcion_con_ruta_absoluta():
    assert VLLM.analizar_argv(["python", "-m", "vllm.entrypoints.openai.api_server", "--model", "/privado/m"])["model"] == "m"


def test_vllm_abreviaturas_de_argparse():
    assert VLLM.analizar_argv(["vllm", "serve", "m", "--api-k", CANARIO])["api_key"] is True
    # «--a» es ambiguo: no se atribuye a ninguna opción y su valor no se guarda.
    assert "api_key" not in VLLM.analizar_argv(["vllm", "serve", "m", "--a", CANARIO])


def test_llamacpp_no_admite_abreviaturas():
    assert LLAMA.analizar_argv(["llama-server", "--api-k", CANARIO]) == {}


def test_vllm_frontend_rust_oculta_args_json():
    opciones = VLLM.analizar_argv(["/v/vllm-rs", "frontend", "--listen-fd", "9", "--args-json", f'{{"api_key":["{CANARIO}"]}}'])
    assert opciones == {"args_json": True}


def test_vllm_hf_token_sin_valor_no_se_traga_la_siguiente():
    assert VLLM.analizar_argv(["vllm", "serve", "m", "--hf-token", "--port", "9000"]) == {
        "model": "m", "hf_token": True, "port": "9000"}


# ------------------------------------------------- tablas: privacidad por construcción
@pytest.mark.parametrize("perfil", PERFILES, ids=lambda p: p.id)
def test_opciones_con_nombre_sensible_son_secretas_o_rutas(perfil):
    for nombre, op in perfil.opciones.items():
        if re.search(r"key|token|secret|password", nombre) and op.valor:
            assert op.secreto or op.es_ruta, nombre


@pytest.mark.parametrize("perfil", PERFILES, ids=lambda p: p.id)
def test_variables_sensibles_se_guardan_como_presencia(perfil):
    for nombre, secreto in perfil.variables.items():
        if re.search(r"KEY|TOKEN|SECRET|PASSWORD|(_FILE|_PATH|_DIR|_URL)$", nombre):
            assert secreto, nombre


# ----------------------------------------------------------------- reconocer proceso
@pytest.mark.parametrize("argv", [
    [r"F:\x\llama-server.exe", "-m", "a"], ["/usr/bin/llama-server"], ["LLAMA-SERVER.EXE"],
    ["/opt/llama", "serve", "-m", "a"],
])
def test_llamacpp_reconoce(argv):
    assert LLAMA.reconoce_proceso(argv)


@pytest.mark.parametrize("argv", [
    [], ["llama-cli", "-m", "a"], ["python", "llama-server"], ["llama", "run"], ["grep", "llama-server"],
    ["vllm", "serve", "m"],
])
def test_llamacpp_no_reconoce(argv):
    assert not LLAMA.reconoce_proceso(argv)


@pytest.mark.parametrize("argv", [
    ["/v/bin/python3.12", "/v/bin/vllm", "serve", "m"], ["vllm", "serve", "m"],
    ["python", "-m", "vllm.entrypoints.openai.api_server", "--model", "m"],
    ["python3", "-m", "vllm.entrypoints.launchers.api_server.entry", "--model", "m"],
    ["/v/vllm/vllm-rs", "frontend", "--listen-fd", "3"],
    ["VLLM::EngineCore_DP0"], ["VLLM::Worker_TP0"], ["VLLM::APIServer_1"], ["VLLM::DPCoordinator"],
])
def test_vllm_reconoce(argv):
    assert VLLM.reconoce_proceso(argv)


@pytest.mark.parametrize("argv", [
    [], ["grep", "vllm", "serve"], ["python", "-c", "vllm serve"], ["vim", "vllm.py"], ["vllm", "chat"],
    ["llama-server"], ["python", "app.py"],
])
def test_vllm_no_reconoce(argv):
    assert not VLLM.reconoce_proceso(argv)


# -------------------------------------------------------------------- puerto y host
def test_llamacpp_puerto_y_host():
    assert LLAMA.puerto_y_host({"host": "0.0.0.0", "port": "8081"}) == ("0.0.0.0", 8081)
    assert LLAMA.puerto_y_host({}) == (None, None)              # el defecto depende de la versión
    assert LLAMA.puerto_y_host({"port": "99999"}) == (None, None)
    assert LLAMA.puerto_y_host({"host": "x.sock", "port": "1"}) == (None, None)


def test_llamacpp_la_opcion_gana_a_la_variable():
    entorno = {"LLAMA_ARG_HOST": "0.0.0.0", "LLAMA_ARG_PORT": "7000"}
    assert LLAMA.puerto_y_host({}, entorno) == ("0.0.0.0", 7000)
    assert LLAMA.puerto_y_host({"port": "8"}, entorno) == ("0.0.0.0", 8)


def test_vllm_puerto_y_host():
    assert VLLM.puerto_y_host({"model": "m"}) == (None, 8000)
    assert VLLM.puerto_y_host({"host": "127.0.0.1", "port": "9"}) == ("127.0.0.1", 9)
    assert VLLM.puerto_y_host({"uds": "a.sock"}) == (None, None)
    assert VLLM.puerto_y_host({}) == (None, None)               # hijo: solo se ve su título


def test_valores_por_defecto_de_cada_perfil():
    assert LLAMA.puertos_defecto == (9931, 8080) and LLAMA.enlace_defecto == "loopback"
    assert VLLM.puertos_defecto == (8000,) and VLLM.enlace_defecto == "todas"
    assert VLLM.post_permitidos == frozenset()
    assert LLAMA.post_permitidos == frozenset({"/slots/0?action=mrrobotia-noop"})


def test_esquema_y_prefijo():
    assert LLAMA.esquema_de({"ssl_cert_file": "c.pem"}) == "https" and LLAMA.esquema_de({}) == "http"
    assert VLLM.esquema_de({"ssl_certfile": "c.pem"}) == "https"
    assert LLAMA.prefijo_de({"api_prefix": "/lab/"}) == "/lab"
    assert VLLM.prefijo_de({"root_path": "/api"}) == "/api"


def test_autenticacion_por_arranque():
    assert LLAMA.autenticacion_de({"api_key": True}) == "activa"
    assert LLAMA.autenticacion_de({"api_key_file": "k"}) == "activa"
    assert LLAMA.autenticacion_de({}, {"LLAMA_API_KEY": True}) == "activa"
    assert VLLM.autenticacion_de({}, {"VLLM_API_KEY": True}) == "activa"
    assert LLAMA.autenticacion_de({}) is None                    # podría venir del entorno


# --------------------------------------------------------- identificar_http: llama.cpp
def test_llamacpp_abierto():
    ident, rutas = identificar(LLAMA, llamacpp())
    assert (ident.tipo, ident.confianza, ident.version, ident.autenticacion) == ("llama.cpp", "alta", BUILD_LLAMACPP, "abierta")
    assert ident.modelos == ["modelo-falso-q4.gguf"]
    assert RUTA_MODELO_FALSA not in repr(ident)
    assert rutas == [("GET", "/health"), ("GET", "/props")]     # lo mínimo y sin efectos


def test_llamacpp_con_clave_da_la_version_publica():
    ident, rutas = identificar(LLAMA, llamacpp(clave="k"))
    assert (ident.confianza, ident.version, ident.autenticacion) == ("alta", "b11583", "activa")
    assert ("GET", "/build.json") in rutas
    assert any(r.startswith("/mrrobotia-") for _, r in rutas)   # confirmación con ruta inexistente


def test_llamacpp_con_clave_y_sin_webui():
    ident, _ = identificar(LLAMA, llamacpp(clave="k", webui=False))
    assert (ident.confianza, ident.version, ident.autenticacion) == ("alta", None, "activa")


def test_llamacpp_prefijo_desconocido_es_indeterminado():
    ident, _ = identificar(LLAMA, llamacpp(prefijo="/lab"))
    assert (ident.tipo, ident.confianza, ident.autenticacion) == ("llama.cpp", "media", "indeterminada")


def test_llamacpp_prefijo_conocido():
    ident, _ = identificar(LLAMA, llamacpp(prefijo="/lab"), "/lab")
    assert (ident.confianza, ident.version, ident.autenticacion) == ("alta", BUILD_LLAMACPP, "abierta")


def test_llamacpp_cargando_es_indeterminado():
    ident, _ = identificar(LLAMA, llamacpp(cargando=True))
    assert ident.tipo == "llama.cpp" and ident.autenticacion == "indeterminada"


def test_llamacpp_tras_proxy_que_cambia_server():
    ident, _ = identificar(LLAMA, llamacpp(server="nginx"))
    assert (ident.tipo, ident.confianza, ident.version) == ("llama.cpp", "alta", BUILD_LLAMACPP)


def test_llamacpp_401_pero_ruta_inexistente_404_no_afirma_clave():
    respuestas = {"GET /props": (401, {"Server": "llama.cpp"}, b"{}"), "GET /health": (200, {"Server": "llama.cpp"}, b"{}")}
    ident, _ = identificar(LLAMA, desde_rutas(respuestas))
    assert ident.autenticacion == "indeterminada"


def test_llamacpp_version_con_marcado_se_descarta():
    ident, _ = identificar(LLAMA, llamacpp(build="[x](http://malo)-1"))
    assert ident.version is None


@pytest.mark.parametrize("responder", [vllm(), generico_openai(), http_simple], ids=["vllm", "generico", "http"])
def test_llamacpp_no_se_atribuye_lo_ajeno(responder):
    assert identificar(LLAMA, responder)[0] is None


# -------------------------------------------------------------- identificar_http: vLLM
def test_vllm_abierto():
    ident, rutas = identificar(VLLM, vllm())
    assert (ident.tipo, ident.confianza, ident.version, ident.autenticacion) == ("vllm", "alta", "0.33.0", "abierta")
    assert ident.modelos == ["org/modelo-falso"]
    assert {m for m, _ in rutas} == {"GET"}


def test_vllm_con_clave():
    ident, _ = identificar(VLLM, vllm(clave="k"))
    assert (ident.confianza, ident.version, ident.autenticacion) == ("alta", "0.33.0", "activa")


def test_vllm_sin_metricas_pero_con_modelos():
    ident, _ = identificar(VLLM, vllm(metricas=False))
    assert ident.confianza == "alta" and ident.autenticacion == "abierta"


def test_vllm_frontend_rust():
    ident, _ = identificar(VLLM, vllm(rust=True, metricas=False, clave="k", server=None))
    assert ident.confianza == "alta" and "frontend Rust" in ident.senales


def test_vllm_solo_version_y_uvicorn_es_media():
    ident, _ = identificar(VLLM, vllm(clave="k", metricas=False, docs=False))
    assert (ident.confianza, ident.autenticacion) == ("media", "activa")


def test_vllm_401_exacto_y_openapi_es_media():
    respuestas = {
        "GET /v1/models": (401, {}, b'{"error":"Unauthorized"}'),
        "GET /openapi.json": (200, {}, b'{"paths":{"/tokenize":{},"/detokenize":{}}}'),
    }
    ident, _ = identificar(VLLM, desde_rutas(respuestas))
    assert (ident.confianza, ident.version, ident.autenticacion) == ("media", None, "activa")


def test_vllm_401_de_un_proxy_no_se_deduce():
    assert identificar(VLLM, desde_rutas({"GET /v1/models": (401, {}, b'{"error":"otra cosa"}')}))[0] is None


def test_vllm_autenticacion_tras_proxy_es_indeterminada():
    def responder(p):
        if p.ruta == "/v1/models":
            return 403, {"Server": "uvicorn"}, b'{"detail":"prohibido"}'
        return vllm()(p)

    ident, _ = identificar(VLLM, responder)
    assert ident.tipo == "vllm" and ident.autenticacion == "indeterminada"


def test_vllm_metrics_solo_si_version_tiene_su_forma():
    _, rutas = identificar(VLLM, llamacpp(server="nginx"))
    assert ("GET", "/metrics") not in rutas


@pytest.mark.parametrize("responder", [generico_openai(), http_simple], ids=["generico", "http"])
def test_vllm_no_se_atribuye_lo_ajeno(responder):
    assert identificar(VLLM, responder)[0] is None


def test_vllm_otra_forma_de_version_no_vale():
    respuestas = {"GET /version": (200, {"Server": "uvicorn"}, b'{"version":"1","deployment_id":"x"}')}
    assert identificar(VLLM, desde_rutas(respuestas))[0] is None


# ----------------------------------------------------------- genérico y registro
def test_generico_abierto_y_con_clave():
    ident, _ = identificar(GENERICO, generico_openai())
    assert (ident.tipo, ident.confianza, ident.autenticacion, ident.modelos) == ("generico", "baja", "abierta", ["alias-falso"])
    ident, _ = identificar(GENERICO, generico_openai(clave="k"))
    assert (ident.tipo, ident.autenticacion) == ("generico", "activa")


def test_generico_no_reconoce_otros_servicios():
    assert identificar(GENERICO, http_simple)[0] is None


def test_registro_de_perfiles():
    assert [p.id for p in PERFILES] == ["llama.cpp", "vllm"]    # el orden importa
    assert por_id("vllm") is VLLM and por_id("generico") is GENERICO and por_id("nada") is None
    assert perfil_de(ServidorDetectado("llama.cpp", "h", 1)) is LLAMA
    assert perfil_de(ServidorDetectado("otro:ollama", "h", 1)) is GENERICO


@pytest.mark.parametrize("perfil", [*PERFILES, GENERICO], ids=lambda p: p.id)
def test_partes_de_otros_hitos_devuelven_lista(perfil):
    servidor = ServidorDetectado(perfil.id, "h", 1)
    assert perfil.evaluar_arranque(servidor, False) == []
    assert perfil.sondear(None, servidor, False, False) == []
