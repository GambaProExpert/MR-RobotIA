"""
Perfil de vLLM. Datos leídos del código de la versión 0.33.0.

Solo GET y sin POST permitidos: varias rutas actúan con un POST vacío. Una ruta que solo admite
POST se detecta con un GET (405 existe, 404 no) y el manejador nunca llega a ejecutarse. `/metrics`
únicamente se pide si `/version` ya tiene la forma de vLLM, para no tocar los indicadores de un
llama.cpp que un proxy hubiera dejado sin reconocer.

Nada de lo de este perfil se ha verificado contra un vLLM real: sale de leer su código y su
documentación, y las pruebas usan un servidor falso que sigue esa misma lectura.
"""
from __future__ import annotations

import json
import secrets

from mrrobotia import cve, procesos
from mrrobotia.nucleo import Severidad
from mrrobotia.perfiles.base import (
    MAX_MODELOS, REFS_EXPO, REFS_FUGA, REFS_SECRETOS, REFS_SUPPLY, Identificacion, Op, Perfil, graduar,
    hallazgo_autenticacion, hallazgo_modelos, limpiar, nombre_fichero, nombre_modelo, normalizar_prefijo,
    version_segura,
)
from mrrobotia.perfiles.base import hallazgo_arranque as _a
from mrrobotia.perfiles.base import hallazgo_exposicion as _h
from mrrobotia.red import a_puerto, clasificar_direccion, es_no_loopback

PUERTO_DEFECTO = 8000
_TITULOS_HIJOS = ("VLLM::EngineCore", "VLLM::Worker", "VLLM::APIServer", "VLLM::DPCoordinator")
_MODULOS_API = ("vllm.entrypoints.openai.api_server", "vllm.entrypoints.launchers.api_server")

# Puertos por defecto de los canales internos. Ninguno tiene autenticación: solo se señalan
# fuera de loopback y, como mucho, se comprueba que acepten una conexión; nunca se les habla.
PUERTOS_INTERNOS = {
    5557: "eventos KV (ZMQ)",
    5600: "canal lateral NIXL",
    8265: "panel de Ray",
    8998: "arranque de Mooncake",
    9256: "supervisor de data parallel",
    10001: "cliente de Ray",
    14579: "transferencia KV",
    29500: "maestro de data parallel",
    29501: "master_port de torch.distributed",
    29550: "RPC de data parallel",
}

# Rutas que solo admiten POST. Quedan fuera de los prefijos que protege --api-key.
RUTA_DESARROLLO = "/collective_rpc"     # solo existe con VLLM_SERVER_DEV_MODE=1
RUTAS_INFERENCIA = ("/invocations", "/generative_scoring", "/pooling", "/classify", "/score", "/rerank")
RUTAS_CONTROL = ("/scale_elastic_ep", "/abort_requests", "/start_profile", "/stop_profile", "/fault_tolerance/apply")


def _bandera(clave):
    """Entradas de una bandera booleana de argparse (`--x` y `--no-x`)."""
    nombre = "--" + clave.replace("_", "-")
    return {nombre: Op(clave, valor=False, fija=True),
            "--no-" + nombre[2:]: Op(clave, valor=False, fija=False)}


OPCIONES = {
    # Red y transporte
    "--host": Op("host"),
    "--port": Op("port"),
    "--uds": Op("uds", es_ruta=True),
    "--root-path": Op("root_path"),
    "--ssl-keyfile": Op("ssl_keyfile", es_ruta=True),
    "--ssl-certfile": Op("ssl_certfile", es_ruta=True),
    "--ssl-ca-certs": Op("ssl_ca_certs", es_ruta=True),
    "--ssl-cert-reqs": Op("ssl_cert_reqs"),
    "--grpc-port": Op("grpc_port"),
    **_bandera("grpc"),
    # Autenticación y CORS. --args-json es la forma en que llega todo al frontend Rust.
    "--api-key": Op("api_key", secreto=True),
    "--args-json": Op("args_json", secreto=True),
    "--hf-token": Op("hf_token", secreto=True),
    "--allowed-origins": Op("allowed_origins"),
    "--allowed-methods": Op("allowed_methods"),
    "--allowed-headers": Op("allowed_headers"),
    **_bandera("allow_credentials"),
    # Documentación, confianza y medios
    **_bandera("disable_fastapi_docs"),
    **_bandera("enable_offline_docs"),
    **_bandera("trust_remote_code"),
    **_bandera("trust_request_chat_template"),
    **_bandera("trust_request_mm_kwargs"),
    "--allowed-local-media-path": Op("allowed_local_media_path", es_ruta=True),
    "--allowed-media-domains": Op("allowed_media_domains"),
    # Rutas y funciones opcionales
    **_bandera("enable_tokenizer_info_endpoint"),
    **_bandera("enable_server_load_tracking"),
    **_bandera("tokens_only"),
    **_bandera("enable_scale_out"),
    **_bandera("enable_fault_tolerance"),
    "--tool-server": Op("tool_server"),
    "--profiler-config": Op("profiler_config", secreto=True),
    "--fingerprint-mode": Op("fingerprint_mode"),
    # Registros
    **_bandera("enable_log_requests"),
    **_bandera("enable_log_outputs"),
    # Código que se importa
    "--middleware": Op("middleware", es_ruta=True),
    "--tool-parser-plugin": Op("tool_parser_plugin", es_ruta=True),
    "--reasoning-parser-plugin": Op("reasoning_parser_plugin", es_ruta=True),
    "--worker-extension-cls": Op("worker_extension_cls", es_ruta=True),
    # Modelo y fichero de configuración
    "--model": Op("model"),
    "--served-model-name": Op("served_model_name"),
    "--config": Op("config", es_ruta=True),
}

# Nombre -> ¿secreta? Las variables con ruta o código también se guardan solo como presencia.
VARIABLES = {
    "VLLM_API_KEY": True,
    "HF_TOKEN": True,
    "VLLM_SERVER_DEV_MODE": False,
    "VLLM_ALLOW_RUNTIME_LORA_UPDATING": False,
    "VLLM_ALLOW_INSECURE_SERIALIZATION": False,
    "VLLM_DEBUG_LOG_API_SERVER_RESPONSE": False,
    "VLLM_LOGGING_LEVEL": False,
    "VLLM_REQUEST_BODY_LOG_LEVEL": False,
    "VLLM_MEDIA_URL_ALLOW_REDIRECTS": False,
    "VLLM_MAX_N_SEQUENCES": False,
    "VLLM_PLUGINS": False,
    "VLLM_GPT_OSS_SYSTEM_TOOL_MCP_LABELS": False,
    "VLLM_ENABLE_RESPONSES_API_STORE": False,
    "VLLM_NO_USAGE_STATS": False,
    "VLLM_DO_NOT_TRACK": False,
    "DO_NOT_TRACK": False,
    "VLLM_USE_RUST_FRONTEND": False,
    "VLLM_HOST_IP": False,
    "VLLM_RPC_BASE_PATH": True,
    "VLLM_PROCESS_NAME_PREFIX": False,
    "CUSTOM_FASTAPI_PING_HANDLER": True,
    "CUSTOM_FASTAPI_INVOCATION_HANDLER": True,
    "CUSTOM_PRE_PROCESS": True,
    "CUSTOM_POST_PROCESS": True,
    "SAGEMAKER_MODEL_PATH": True,
    "CUSTOM_SCRIPT_FILENAME": True,
}


_VALORES_FALSOS = {"off", "disabled", "false", "0", ""}
_VARIABLES_TELEMETRIA = ("VLLM_NO_USAGE_STATS", "VLLM_DO_NOT_TRACK", "DO_NOT_TRACK")
# Antes de esta versión, --allowed-origins valía ["*"] por defecto.
_VERSION_CORS_RESTRINGIDO = "0.32.0"

_INFO, _BAJA, _MEDIA, _ALTA, _CRITICA = (Severidad.INFO, Severidad.BAJA, Severidad.MEDIA, Severidad.ALTA,
                                         Severidad.CRITICA)
# Opciones que por sí mismas suponen un riesgo (`vllm.md` §5.1):
# (opciones, fila, título, en loopback, expuesto, recomendación, marcos).
_FILAS_OPCION = (
    (("trust_remote_code",), "TRUST-REMOTE-CODE", "Se ejecuta código del repositorio del modelo", _ALTA, _ALTA,
     "Retira --trust-remote-code salvo que confíes en ese repositorio y fijes su revisión.", REFS_SUPPLY),
    (("allowed_local_media_path",), "MEDIA-PATH", "Lectura de ficheros locales desde las peticiones", _MEDIA, _ALTA,
     "Limita ese directorio a lo imprescindible o retira la opción.", REFS_FUGA),
    (("enable_tokenizer_info_endpoint",), "TOKENIZER-INFO", "/tokenizer_info activado", _BAJA, _MEDIA,
     "Retira --enable-tokenizer-info-endpoint: publica las plantillas de chat sin clave.", REFS_FUGA),
    (("enable_log_outputs",), "LOG-SALIDAS", "El texto generado se escribe en el registro", _MEDIA, _MEDIA,
     "Retira --enable-log-outputs fuera de una depuración puntual.", REFS_FUGA),
    (("enable_server_load_tracking",), "LOAD", "Contador de carga activado", _INFO, _BAJA,
     "/load publica sin clave la carga del servidor: retíralo si no lo usas.", REFS_EXPO),
    (("trust_request_chat_template",), "CHAT-TEMPLATE-CLIENTE", "Se aceptan plantillas de chat del cliente", _BAJA, _MEDIA,
     "Retira --trust-request-chat-template: el cliente controla una plantilla Jinja.", REFS_EXPO),
    (("trust_request_mm_kwargs",), "MM-KWARGS-CLIENTE", "Se aceptan parámetros multimodales del cliente", _BAJA, _MEDIA,
     "Retira --trust-request-mm-kwargs si no lo necesitas.", REFS_EXPO),
    (("tokens_only",), "TOKENS-ONLY", "--tokens-only abre POST /abort_requests sin clave", _BAJA, _ALTA,
     "No lo expongas: cualquiera que alcance el puerto puede abortar peticiones.", REFS_EXPO),
    (("enable_scale_out",), "SCALE-OUT", "Rutas de scale-out activadas", _BAJA, _MEDIA,
     "Si no las usas, retira --enable-scale-out.", REFS_EXPO),
    (("profiler_config",), "PROFILER", "--profiler-config abre el control del perfilador sin clave", _BAJA, _ALTA,
     "Retíralo fuera de una medición puntual: /start_profile y /stop_profile no piden clave.", REFS_EXPO),
    (("enable_fault_tolerance",), "FAULT-TOLERANCE", "--enable-fault-tolerance abre sus rutas sin clave", _BAJA, _ALTA,
     "No lo expongas: /fault_tolerance/apply no pide clave y dispara una recuperación.", REFS_EXPO),
    (("grpc", "grpc_port"), "GRPC", "Puerto gRPC sin autenticación ni cifrado", _MEDIA, _ALTA,
     "Enlaza ese puerto a loopback o aíslalo en una red de confianza.", REFS_EXPO),
    (("hf_token",), "HF-TOKEN", "Token de Hugging Face en la línea de órdenes", _MEDIA, _MEDIA,
     "Usa la variable HF_TOKEN o un gestor de secretos.", REFS_SECRETOS),
)
# Variables con riesgo propio (`vllm.md` §5.2): (variable, fila, título, en loopback, expuesto, recomendación, marcos).
_FILAS_VARIABLE = (
    ("VLLM_SERVER_DEV_MODE", "DESARROLLO", "Modo desarrollo activado", _ALTA, _CRITICA,
     "Retira VLLM_SERVER_DEV_MODE: abre sin clave rutas que ejecutan métodos del motor (A5).", REFS_EXPO),
    ("VLLM_ALLOW_RUNTIME_LORA_UPDATING", "LORA-DINAMICO", "Se pueden cargar y descargar adaptadores en caliente",
     _MEDIA, _ALTA, "Retira esa variable si no lo necesitas: cambia el comportamiento del modelo en ejecución.", REFS_EXPO),
    ("VLLM_ALLOW_INSECURE_SERIALIZATION", "SERIALIZACION-INSEGURA", "Se permite la serialización insegura (pickle)",
     _ALTA, _ALTA, "Retira esa variable: pickle permite ejecutar código a quien alcance esos canales.", REFS_SUPPLY),
    ("VLLM_DEBUG_LOG_API_SERVER_RESPONSE", "LOG-RESPUESTAS", "Los cuerpos de las respuestas se escriben en el registro",
     _MEDIA, _ALTA, "Retira esa variable fuera de una depuración puntual.", REFS_FUGA),
    ("VLLM_GPT_OSS_SYSTEM_TOOL_MCP_LABELS", "MCP", "Herramientas internas por MCP configuradas", _BAJA, _MEDIA,
     "Revisa qué permiten esos servidores: el modelo podrá invocarlos.", REFS_EXPO),
    ("VLLM_ENABLE_RESPONSES_API_STORE", "RESPUESTAS-GUARDADAS", "Se guardan las respuestas generadas", _BAJA, _MEDIA,
     "Retira esa variable si no necesitas conservarlas: quedan en el servidor.", REFS_FUGA),
    ("VLLM_MEDIA_URL_ALLOW_REDIRECTS", "MEDIA-REDIRECCIONES", "Se siguen redirecciones al descargar medios", _INFO, _BAJA,
     "Ponla a 0 si no la necesitas: las redirecciones facilitan llegar a redes internas.", REFS_EXPO),
    ("VLLM_MAX_N_SEQUENCES", "MAX-SEQUENCES", "Tope del parámetro n definido a mano", _INFO, _BAJA,
     "Mantenlo bajo: un valor alto facilita agotar los recursos con una sola petición.", REFS_EXPO),
)
# Sin riesgo propio: se resumen en un único hallazgo (`vllm.md` §5.1 y §5.2).
_OPCIONES_INVENTARIO = ("port", "uds", "allowed_methods", "allowed_headers", "enable_offline_docs", "ssl_cert_reqs",
                        "tool_server", "middleware", "tool_parser_plugin", "reasoning_parser_plugin",
                        "worker_extension_cls")
_VARIABLES_INVENTARIO = ("VLLM_PLUGINS", "VLLM_USE_RUST_FRONTEND", "VLLM_HOST_IP", "VLLM_RPC_BASE_PATH",
                         "VLLM_PROCESS_NAME_PREFIX", "CUSTOM_FASTAPI_PING_HANDLER", "CUSTOM_FASTAPI_INVOCATION_HANDLER",
                         "CUSTOM_PRE_PROCESS", "CUSTOM_POST_PROCESS", "SAGEMAKER_MODEL_PATH", "CUSTOM_SCRIPT_FILENAME")


def _es_python(ejecutable):
    return ejecutable.startswith(("python", "pypy"))


def _ejecutable(token):
    return nombre_fichero(token).lower().removesuffix(".exe")


# ----------------------------------------------- sondeo de red: una función por hallazgo
def _sin_concluir(id_, titulo, evidencia):
    return _h(id_, titulo, _INFO, evidencia, "Compruébalo a mano: esto no demuestra que esté protegido.",
              estado="sin_concluir")


def _estado_de(respuesta):
    return respuesta.estado if respuesta.estado is not None else "sin respuesta"


def _explorar(cliente, rutas):
    """(existentes, dudosas) de una lista de rutas que solo admiten POST. Se pregunta con GET: 405
    es que existe y 404 que no; cualquier otra cosa no permite concluir."""
    existentes, dudosas = [], []
    for ruta in rutas:
        estado = cliente.get(ruta).estado
        if estado == 405:
            existentes.append(ruta)
        elif estado != 404:
            dudosas.append(ruta)
    return existentes, dudosas


def _detalle_autenticacion(modelos, autenticacion, servidor):
    """Qué se ha pedido, qué ha respondido y, si no concluye, por qué puede ser."""
    detalle = f"GET /v1/models sin credenciales: {_estado_de(modelos)}"
    if autenticacion != "indeterminada":
        return detalle
    if modelos.estado in (401, 403):
        detalle += " (no es la respuesta de vLLM: puede haber un proxy delante)"
    elif modelos.estado == 503:
        detalle += " (escalado en curso o proceso retirado)"
    if servidor.autenticacion == "activa":
        detalle += "; el arranque configura una clave"
    return detalle


def _hallazgo_version(datos, forma, servidor):
    """`/version`: público aun con clave."""
    if forma:
        servidor.version = version_segura(datos.get("version")) or servidor.version
    evidencia = f"versión = {servidor.version or 'desconocida'}"
    if forma:
        evidencia += "; /version la publica sin clave"
        if "rust_frontend_version" in datos:
            evidencia += "; frontend Rust"
    return _h("H2-BUILD", "Versión de vLLM detectada", _INFO, evidencia, "", REFS_SUPPLY, "informativo")


def _hallazgo_metricas(cliente, expuesto):
    """Solo cuántas series hay: las etiquetas nombran el modelo y el motor."""
    respuesta = cliente.get("/metrics")
    if respuesta.estado != 200:
        return None
    series = sum(1 for linea in respuesta.texto().splitlines() if linea.startswith("vllm:"))
    if not series:
        return None
    return _h("H2-METRICS", "El endpoint /metrics (Prometheus) está accesible", graduar(expuesto, _BAJA, _MEDIA),
              f"/metrics accesible sin clave, {series} serie(s) vllm:",
              "Restringe /metrics en un proxy: --api-key no lo protege y expone métricas de uso (A5).")


def _hallazgo_desarrollo(cliente, expuesto):
    """Con el modo desarrollo, `/collective_rpc` existe y un POST ejecutaría métodos del motor."""
    existentes, dudosas = _explorar(cliente, (RUTA_DESARROLLO,))
    if dudosas:
        return _sin_concluir("H2-DESARROLLO", "No se pudo comprobar el modo desarrollo",
                             f"GET {RUTA_DESARROLLO} no responde ni 404 ni 405")
    if not existentes:
        return _h("H2-DESARROLLO", "El modo desarrollo de vLLM está inactivo", _INFO,
                  f"GET {RUTA_DESARROLLO}: 404", "", estado="informativo")
    return _h("H2-DESARROLLO", "El modo desarrollo de vLLM está activo", graduar(expuesto, _ALTA, _CRITICA),
              f"GET {RUTA_DESARROLLO}: 405, la ruta existe y no pide clave",
              "Retira VLLM_SERVER_DEV_MODE: abre sin clave rutas que ejecutan métodos del motor, vacían sus "
              "cachés, lo pausan o cambian los pesos, aunque haya --api-key (A5).")


def _hallazgo_inferencia(cliente, autenticacion, expuesto, proxy):
    """Con clave, estas rutas siguen abiertas: quedan fuera de los prefijos que protege. Sin clave
    no aportan nada: todo está abierto por la misma causa y eso ya lo dice H2-AUTH."""
    if autenticacion == "abierta":
        return None
    existentes, dudosas = _explorar(cliente, RUTAS_INFERENCIA)
    if not existentes:
        return _sin_concluir("H2-INFERENCIA-SIN-CLAVE", "No se pudieron comprobar las rutas de inferencia sin clave",
                             "no responden ni 404 ni 405: " + ", ".join(dudosas)) if dudosas else None
    severidad = _CRITICA if expuesto and not proxy else graduar(expuesto, _BAJA, _MEDIA)
    return _h("H2-INFERENCIA-SIN-CLAVE", "Hay rutas de inferencia que no exigen la clave de API", severidad,
              "GET responde 405, la ruta existe y no pide clave: " + ", ".join(existentes),
              "--api-key solo protege /v1, /v2, /inference y /cohere: pon delante un proxy que solo deje pasar "
              "esos prefijos, o cualquiera que alcance el puerto podrá usar el modelo (A5).")


def _hallazgo_control(cliente, desarrollo_activo, expuesto):
    """Rutas que reescalan, abortan o perfilan sin clave. `/abort_requests` también existe en modo
    desarrollo, y entonces su causa es esa: ya la cuenta H2-DESARROLLO."""
    rutas = [r for r in RUTAS_CONTROL if not (desarrollo_activo and r == "/abort_requests")]
    existentes, dudosas = _explorar(cliente, rutas)
    if not existentes:
        return _sin_concluir("H2-CONTROL-SIN-CLAVE", "No se pudieron comprobar las rutas de control sin clave",
                             "no responden ni 404 ni 405: " + ", ".join(dudosas)) if dudosas else None
    return _h("H2-CONTROL-SIN-CLAVE", "Hay rutas de control que no exigen clave", graduar(expuesto, _BAJA, _ALTA),
              "GET responde 405, la ruta existe y no pide clave: " + ", ".join(existentes),
              "Restríngelas en un proxy: --api-key no las protege y permiten reescalar el motor, abortar peticiones "
              "o controlar el perfilador (A5).")


def _hallazgo_openapi(cliente, expuesto):
    respuesta = cliente.get("/openapi.json")
    datos = respuesta.json() if respuesta.estado == 200 else None
    rutas = datos.get("paths") if isinstance(datos, dict) else None
    if not isinstance(rutas, dict):
        return None
    return _h("H2-OPENAPI", "La documentación OpenAPI está abierta", graduar(expuesto, _BAJA, _MEDIA),
              f"/openapi.json accesible sin clave: {len(rutas)} ruta(s)",
              "Arranca con --disable-fastapi-docs: publica el mapa de la API a quien alcance el puerto (A5).")


def _hallazgo_carga(cliente, expuesto):
    respuesta = cliente.get("/load")
    datos = respuesta.json() if respuesta.estado == 200 else None
    if not isinstance(datos, dict) or "server_load" not in datos:
        return None
    severidad = graduar(expuesto, _INFO, _BAJA)
    return _h("H2-LOAD", "El endpoint /load publica la carga del servidor", severidad,
              "/load accesible sin clave (no se vuelca su contenido)", "Restríngelo en un proxy: --api-key no lo protege.",
              estado="informativo" if severidad == _INFO else "confirmado")


def _hallazgo_eventos_kv(cliente, expuesto):
    """Sin eventos KV es `{}` y no hay nada que contar; con ellos, puede revelar direcciones internas."""
    respuesta = cliente.get("/kv_event_sources")
    datos = respuesta.json() if respuesta.estado == 200 else None
    if not isinstance(datos, (dict, list)) or not datos:
        return None
    return _h("H2-KV-EVENTS", "El endpoint /kv_event_sources publica los canales internos", graduar(expuesto, _BAJA, _MEDIA),
              f"/kv_event_sources accesible sin clave, {len(datos)} entrada(s) (no se vuelca su contenido)",
              "Restríngelo en un proxy: --api-key no lo protege y puede revelar direcciones internas (A5).", REFS_FUGA)


def _hallazgo_tokenizador(cliente, expuesto):
    """Solo importa si responde: el cuerpo lleva plantillas de chat y no se mira."""
    if cliente.get("/tokenizer_info").estado != 200:
        return None
    return _h("H2-TOKENIZER-INFO", "El endpoint /tokenizer_info está accesible", graduar(expuesto, _BAJA, _MEDIA),
              "/tokenizer_info accesible sin clave (no se vuelca su contenido)",
              "Retira --enable-tokenizer-info-endpoint: publica las plantillas de chat, que pueden incluir el "
              "system prompt (LLM02).", REFS_FUGA)


# ---------------------------------------------------- arranque: `vllm.md` §§5.1-5.3
def _activa(valor):
    """¿Activa este valor de opción o variable? Un secreto (True) cuenta como presente."""
    if valor is None or valor is False:
        return False
    return valor is True or str(valor).strip().lower() not in _VALORES_FALSOS


def _entorno_legible(s):
    """¿Se ha podido mirar el entorno del proceso? Si no, lo que falta en él no se puede afirmar."""
    return bool(s.entorno) or (s.pid is not None and procesos.entorno_legible(s.pid))


def _arranque_enlace(s):
    """Siempre ALTA: la combinación con la falta de clave ya la da `SIN-CLAVE`. Sin --host, vLLM
    escucha en todas las interfaces IPv4, pero la opción podría estar en un --config."""
    if "uds" in s.opciones:
        return None
    host = s.opciones.get("host")
    recomendacion = "Usa --host 127.0.0.1 y pon delante un proxy con autenticación si necesitas acceso remoto (A5)."
    if host is None:
        return _a("HOST", "Arrancado para escuchar en todas las interfaces", _ALTA,
                  "no consta --host: por defecto, todas las interfaces IPv4", recomendacion, estado="potencial")
    if not es_no_loopback(clasificar_direccion(host)):
        return None
    return _a("HOST", "Arrancado para escuchar fuera de loopback", _ALTA, f"--host {limpiar(host)}", recomendacion)


def _arranque_clave(s, expuesto):
    filas = []
    if s.opciones.get("api_key") is True:
        filas.append(_a("CLAVE-EN-ORDEN", "La clave de API está en la línea de órdenes", _MEDIA,
                        "--api-key presente en la línea de órdenes (no se conserva su valor)",
                        "Usa VLLM_API_KEY: la línea de órdenes de un proceso la pueden leer otros usuarios del equipo "
                        "y queda en los registros.", REFS_SECRETOS))
    elif s.opciones.get("args_json") is True:
        filas.append(_a("CLAVE-EN-ORDEN", "La línea de órdenes del frontend Rust puede llevar la clave", _MEDIA,
                        "--args-json presente: si la clave se dio con --api-key, va en él (no se conserva su valor)",
                        "Usa VLLM_API_KEY: el contenido de --args-json lo pueden leer otros usuarios del equipo.",
                        REFS_SECRETOS, "potencial"))
    if s.autenticacion != "activa":
        abierta = s.autenticacion == "abierta"
        filas.append(_a("SIN-CLAVE", "El servidor arranca sin clave de API", graduar(expuesto, _BAJA, _CRITICA),
                        "no consta --api-key ni VLLM_API_KEY"
                        + ("; responde sin credenciales" if abierta else "; podría venir del entorno, que no siempre es legible"),
                        "Arranca con la variable VLLM_API_KEY (A5).", estado="confirmado" if abierta else "potencial"))
    return filas


def _arranque_tls(s, expuesto):
    if s.opciones.get("ssl_certfile") or s.opciones.get("ssl_keyfile"):
        return None
    return _a("TLS", "El servidor arranca sin TLS", graduar(expuesto, _BAJA, _ALTA),
              "no consta --ssl-keyfile ni --ssl-certfile",
              "Usa --ssl-keyfile y --ssl-certfile, o un proxy inverso con HTTPS, si el tráfico sale del equipo.",
              estado="confirmado" if s.esquema == "http" and "http" in s.fuentes else "potencial")


def _admite_cualquier_origen(valor):
    """`--allowed-origins` es JSON: `["*"]`."""
    try:
        lista = json.loads(valor)
    except (TypeError, ValueError):
        return str(valor).strip() == "*"
    return isinstance(lista, list) and "*" in lista


def _arranque_cors(s, expuesto):
    origenes = s.opciones.get("allowed_origins")
    if origenes is True:        # llevaba una URL con credenciales: solo se guardó su presencia
        return None
    if origenes is None:
        clave = cve.clave_pep440(s.version)
        if clave is None or clave >= cve.clave_pep440(_VERSION_CORS_RESTRINGIDO):
            return None
    elif not _admite_cualquier_origen(origenes):
        return None
    credenciales = s.opciones.get("allow_credentials") is True
    return _a("CORS", "CORS permite cualquier origen", graduar(expuesto, _BAJA, _MEDIA),
              f"allowed_origins=*, credenciales={'sí' if credenciales else 'no'}"
              + ("" if origenes is not None else f" (valor por defecto hasta {_VERSION_CORS_RESTRINGIDO})"),
              "Fija --allowed-origins al origen de tu aplicación: con el comodín, cualquier web podría leer las "
              "respuestas desde el navegador de la víctima (A5).",
              estado="confirmado" if origenes is not None else "potencial")


def _arranque_por_tabla(s, expuesto):
    filas = []
    for claves, fila, titulo, en_loopback, en_red, recomendacion, refs in _FILAS_OPCION:
        vistas = [c for c in claves if _activa(s.opciones.get(c))]
        if vistas:
            severidad = graduar(expuesto, en_loopback, en_red)
            filas.append(_a(fila, titulo, severidad, f"--{vistas[0].replace('_', '-')} presente", recomendacion, refs,
                            "informativo" if severidad == _INFO else "confirmado"))
    for variable, fila, titulo, en_loopback, en_red, recomendacion, refs in _FILAS_VARIABLE:
        if _activa(s.entorno.get(variable)):
            severidad = graduar(expuesto, en_loopback, en_red)
            filas.append(_a(fila, titulo, severidad, f"{variable} definida", recomendacion, refs,
                            "informativo" if severidad == _INFO else "confirmado"))
    return filas


def _arranque_registros(s):
    """--enable-log-requests registra parámetros, y con el nivel DEBUG también los prompts."""
    if s.opciones.get("enable_log_requests") is not True:
        return None
    depuracion = str(s.entorno.get("VLLM_LOGGING_LEVEL", "")).strip().upper() == "DEBUG"
    return _a("LOG-PROMPTS", "Las peticiones se escriben en el registro", _ALTA if depuracion else _MEDIA,
              "--enable-log-requests presente" + ("; VLLM_LOGGING_LEVEL=DEBUG" if depuracion else ""),
              "Retíralo fuera de una depuración puntual: en DEBUG el registro incluye el contenido de los prompts.", REFS_FUGA)


def _arranque_documentacion(s, expuesto):
    if s.opciones.get("disable_fastapi_docs") is True:
        return None
    return _a("OPENAPI", "La documentación OpenAPI está activa", graduar(expuesto, _BAJA, _MEDIA),
              "no consta --disable-fastapi-docs", "Arranca con --disable-fastapi-docs si no la usas.", estado="potencial")


def _arranque_medios(s, expuesto):
    if s.opciones.get("allowed_media_domains"):
        return None
    return _a("MEDIA-DOMINIOS", "Sin restricción de dominios al descargar medios", graduar(expuesto, _BAJA, _MEDIA),
              "no consta --allowed-media-domains; solo afecta a modelos multimodales",
              "Limita los dominios con --allowed-media-domains: sin ella, se facilita alcanzar redes internas (SSRF).",
              estado="potencial")


def _es_servidor_demo(valor):
    return isinstance(valor, str) and "demo" in [t.strip().lower() for t in valor.split(",")]


def _arranque_herramientas(s, expuesto):
    if not _es_servidor_demo(s.opciones.get("tool_server")):
        return None
    return _a("TOOLS", "Servidor de herramientas de demostración activado", graduar(expuesto, _MEDIA, _ALTA),
              "--tool-server demo", "No lo uses fuera de una prueba: ejecuta código generado en Docker sin aislar la red.")


def _arranque_huella(s, expuesto):
    modo = s.opciones.get("fingerprint_mode")
    if modo not in (None, "full"):
        return None
    severidad = graduar(expuesto, _INFO, _BAJA)
    return _a("FINGERPRINT", "La versión se publica en system_fingerprint", severidad,
              "--fingerprint-mode full" if modo else "no consta --fingerprint-mode: por defecto, full",
              "Cambia --fingerprint-mode si no quieres publicar la versión en las respuestas.",
              estado="informativo" if severidad == _INFO else "confirmado" if modo else "potencial")


def _arranque_telemetria(s, legible):
    """Sin exclusión expresa, vLLM envía estadísticas de uso a un servicio externo. Si el entorno no
    se puede leer, no se sabe si la exclusión está puesta."""
    if any(_activa(s.entorno.get(v)) for v in _VARIABLES_TELEMETRIA):
        return None
    if legible:
        return _a("TELEMETRIA", "vLLM envía telemetría de uso al exterior", _BAJA,
                  "no consta VLLM_NO_USAGE_STATS, VLLM_DO_NOT_TRACK ni DO_NOT_TRACK",
                  "Define VLLM_NO_USAGE_STATS=1 o DO_NOT_TRACK=1 si no quieres que salgan datos del equipo.")
    return _a("TELEMETRIA", "Telemetría de vLLM sin comprobar", _BAJA,
              "el entorno del proceso no es legible: no se puede saber si la telemetría está desactivada",
              "Comprueba que VLLM_NO_USAGE_STATS=1 o DO_NOT_TRACK=1 estén definidas si no quieres que salgan datos del equipo.",
              estado="potencial")


def _arranque_informativas(s):
    vistas = [f"{clave}={'presente' if s.opciones[clave] is True else limpiar(s.opciones[clave], 40)}"
              for clave in _OPCIONES_INVENTARIO
              if clave in s.opciones and s.opciones[clave] is not False and not _es_servidor_demo(s.opciones[clave])]
    presentes = [v for v in _VARIABLES_INVENTARIO if v in s.entorno]
    if presentes:
        vistas.append("variables presentes: " + ", ".join(presentes))
    if not vistas:
        return None
    return _a("OTRAS", "Otras opciones de arranque, sin riesgo propio", _INFO, "; ".join(vistas), "", estado="informativo")


def _arranque_fichero_config(s):
    if "config" not in s.opciones:
        return None
    return _a("CONFIG", "Parte del arranque está en un fichero", _INFO,
              "--config presente: no se ha leído, y lo que aquí «no consta» podría estar en él",
              "Revísalo a mano: puede contener opciones y claves.", estado="sin_concluir")


class Vllm(Perfil):
    id = "vllm"
    nombre = "vLLM"
    puertos_defecto = (PUERTO_DEFECTO,)
    puertos_internos = PUERTOS_INTERNOS
    enlace_defecto = "todas"        # sin --host escucha en todas las interfaces IPv4
    opciones = OPCIONES
    variables = VARIABLES
    variables_clave = ("VLLM_API_KEY",)
    post_permitidos = frozenset()
    fichero_cve = "cve_vllm.json"
    clave_version = staticmethod(cve.clave_pep440)
    abreviaturas = True

    # ------------------------------------------------------------ proceso local
    def reconoce_proceso(self, argv) -> bool:
        if not argv:
            return False
        if str(argv[0]).startswith(_TITULOS_HIJOS):
            return True
        indice = 1 if _es_python(_ejecutable(argv[0])) and len(argv) > 1 else 0
        ejecutable = _ejecutable(argv[indice])
        siguiente = argv[indice + 1] if len(argv) > indice + 1 else ""
        if (ejecutable == "vllm" and siguiente == "serve") or (ejecutable == "vllm-rs" and siguiente == "frontend"):
            return True
        return (_es_python(_ejecutable(argv[0])) and len(argv) > 2 and argv[1] == "-m"
                and argv[2].startswith(_MODULOS_API))

    def analizar_argv(self, argv) -> dict:
        opciones = super().analizar_argv(argv)
        modelo = nombre_modelo(opciones.get("model") or self._posicional_serve(argv))
        if modelo:
            opciones["model"] = modelo
        else:
            opciones.pop("model", None)
        return opciones

    @staticmethod
    def _posicional_serve(argv):
        """`vllm serve MODELO`: el modelo es el token que sigue a `serve`, si no es una opción."""
        for i, token in enumerate(argv[:-1]):
            if token == "serve":
                return None if argv[i + 1].startswith("-") else argv[i + 1]
        return None

    def puerto_y_host(self, opciones, entorno=None) -> tuple:
        """Sin opciones es un proceso hijo (solo se ve su título) y no se sabe nada de él."""
        if not opciones or "uds" in opciones:
            return None, None
        return opciones.get("host"), a_puerto(opciones.get("port", PUERTO_DEFECTO))

    def esquema_de(self, opciones, entorno=None) -> str:
        return "https" if opciones.get("ssl_certfile") else "http"

    def prefijo_de(self, opciones, entorno=None) -> str:
        return normalizar_prefijo(opciones.get("root_path"))

    def modelos_de(self, opciones) -> list:
        return [m for m in (opciones.get("served_model_name"), opciones.get("model")) if m]

    # ----------------------------------------------------------------- red
    @staticmethod
    def _forma_version(datos):
        """`/version` tiene una sola clave; el frontend Rust añade `rust_frontend_version`."""
        return (isinstance(datos, dict) and "version" in datos
                and (len(datos) == 1 or "rust_frontend_version" in datos))

    @staticmethod
    def _autenticacion(modelos, es_propio):
        """`/v1/models` sin clave: 200 propio, abierta; 401 exacto, activa. Un 401 o 403 con
        otro cuerpo es un proxy delante y un 503, un escalado: no permiten concluir."""
        if modelos.estado == 200 and es_propio:
            return "abierta"
        if modelos.estado == 401 and modelos.json() == {"error": "Unauthorized"}:
            return "activa"
        return "indeterminada"

    @staticmethod
    def _filas_propias(modelos):
        """Filas de `/v1/models` con `owned_by: vllm`."""
        datos = modelos.json() if modelos.estado == 200 else None
        lista = datos.get("data") if isinstance(datos, dict) else None
        if not isinstance(lista, list):
            return []
        return [d for d in lista if isinstance(d, dict) and d.get("owned_by") == "vllm"]

    def identificar_http(self, cliente) -> Identificacion | None:
        respuesta_version = cliente.get("/version")
        if respuesta_version.estado is None:
            return None
        datos_version = respuesta_version.json() if respuesta_version.estado == 200 else None
        forma = self._forma_version(datos_version)
        series = forma and "vllm:" in cliente.get("/metrics").texto()
        rust = forma and "rust_frontend_version" in datos_version
        uvicorn = "uvicorn" in str(respuesta_version.cabeceras.get("server", "")).lower()

        modelos = cliente.get("/v1/models")
        ids = [d.get("id") for d in self._filas_propias(modelos)]
        autenticacion = self._autenticacion(modelos, bool(ids))
        senales = []
        if forma:
            senales.append("/version con la forma de vLLM")
        if series:
            senales.append("series vllm: en /metrics")
        if rust:
            senales.append("frontend Rust")
        if ids:
            senales.append("/v1/models con owned_by vllm")

        if series or rust or ids:
            confianza = "alta"
        elif autenticacion == "activa" and self._openapi_propio(cliente):
            confianza = "media"
            senales.append("401 exacto y /tokenize en OpenAPI")
        elif forma and uvicorn:
            confianza = "media"
            senales.append("/version y cabecera Server: uvicorn")
        else:
            return None     # sin señal suficiente: no se deduce

        version = version_segura(datos_version.get("version")) if forma else None
        nombres = [n for n in (nombre_modelo(i) for i in ids[:MAX_MODELOS]) if n]
        return Identificacion(self.id, confianza, version, autenticacion, senales, nombres)

    @staticmethod
    def _openapi_propio(cliente):
        """¿La documentación OpenAPI lista las rutas propias de vLLM?"""
        respuesta = cliente.get("/openapi.json")
        datos = respuesta.json() if respuesta.estado == 200 else None
        rutas = datos.get("paths") if isinstance(datos, dict) else None
        return isinstance(rutas, dict) and "/tokenize" in rutas and "/detokenize" in rutas

    # --------------------------------------------- comprobaciones por servidor
    def sondear(self, cliente, servidor, expuesto, proxy) -> list:
        """Lo específico de vLLM, solo con GET. Las rutas se interpretan únicamente si una ruta
        inventada da 404: con un proxy o una ruta comodín delante, los 404 y 405 no significan nada."""
        modelos = cliente.get("/v1/models")
        filas = self._filas_propias(modelos)
        autenticacion = self._autenticacion(modelos, bool(filas))
        detalle = _detalle_autenticacion(modelos, autenticacion, servidor)
        if autenticacion != "indeterminada":        # lo no concluyente no borra lo que dice el arranque
            servidor.autenticacion = autenticacion
        version = cliente.get("/version")
        datos_version = version.json() if version.estado == 200 else None
        forma = self._forma_version(datos_version)
        hallazgos = [
            hallazgo_autenticacion(autenticacion, detalle, "Arranca vLLM con la variable VLLM_API_KEY, o ponlo tras "
                                                           "un proxy que autentique"),
            _hallazgo_version(datos_version, forma, servidor),
            hallazgo_modelos([d["id"] for d in filas if isinstance(d.get("id"), str)], [d.get("root") for d in filas]),
        ]
        if forma:
            hallazgos.append(_hallazgo_metricas(cliente, expuesto))
        control = cliente.get(f"/mrrobotia-{secrets.token_hex(4)}")
        if control.estado == 404:
            hallazgos.extend(self._sondear_rutas(cliente, autenticacion, expuesto, proxy))
        else:
            hallazgos.append(_sin_concluir(
                "H2-RUTAS", "No se pueden comprobar las rutas de vLLM",
                f"una ruta inexistente responde {_estado_de(control)}: un proxy o una ruta comodín hacen que los 404 "
                "y 405 no signifiquen nada"))
        return [h for h in hallazgos if h is not None]

    @staticmethod
    def _sondear_rutas(cliente, autenticacion, expuesto, proxy):
        """Lo que se concluye por la existencia de cada ruta. Nunca se pide `/server_info`."""
        desarrollo = _hallazgo_desarrollo(cliente, expuesto)
        return [desarrollo,
                _hallazgo_inferencia(cliente, autenticacion, expuesto, proxy),
                _hallazgo_control(cliente, desarrollo.severidad != _INFO, expuesto),
                _hallazgo_openapi(cliente, expuesto), _hallazgo_carga(cliente, expuesto),
                _hallazgo_eventos_kv(cliente, expuesto), _hallazgo_tokenizador(cliente, expuesto)]

    def evaluar_arranque(self, servidor, expuesto) -> list:
        """Riesgos de cómo se arrancó (`vllm.md` §§5.1-5.3). Lo que falta en la línea de órdenes o en
        un entorno que no se ha podido leer queda como `potencial`. Solo presencia o valores saneados."""
        filas = [_arranque_fichero_config(servidor), _arranque_enlace(servidor), *_arranque_clave(servidor, expuesto),
                 _arranque_tls(servidor, expuesto), _arranque_cors(servidor, expuesto),
                 _arranque_documentacion(servidor, expuesto), _arranque_medios(servidor, expuesto),
                 *_arranque_por_tabla(servidor, expuesto), _arranque_registros(servidor),
                 _arranque_herramientas(servidor, expuesto), _arranque_huella(servidor, expuesto),
                 _arranque_telemetria(servidor, _entorno_legible(servidor)), _arranque_informativas(servidor)]
        return [h for h in filas if h is not None]

    def componente_en_uso(self, aviso, servidor):
        """Los avisos de vLLM no llevan componente: se dan por aplicables."""
        return True
