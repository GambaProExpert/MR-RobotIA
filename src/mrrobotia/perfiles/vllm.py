"""
Perfil de vLLM. Datos leídos del código de la versión 0.33.0.

Solo GET y sin POST permitidos: varias rutas actúan con un POST vacío. `/metrics` únicamente
se pide si `/version` ya tiene la forma de vLLM, para no tocar los indicadores de un
llama.cpp que un proxy hubiera dejado sin reconocer.
"""
from __future__ import annotations

from mrrobotia.perfiles.base import (
    MAX_MODELOS, Identificacion, Op, Perfil, nombre_fichero, nombre_modelo, normalizar_prefijo,
    version_segura,
)
from mrrobotia.red import a_puerto

PUERTO_DEFECTO = 8000
_TITULOS_HIJOS = ("VLLM::EngineCore", "VLLM::Worker", "VLLM::APIServer", "VLLM::DPCoordinator")
_MODULOS_API = ("vllm.entrypoints.openai.api_server", "vllm.entrypoints.launchers.api_server")


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


def _es_python(ejecutable):
    return ejecutable.startswith(("python", "pypy"))


def _ejecutable(token):
    return nombre_fichero(token).lower().removesuffix(".exe")


class Vllm(Perfil):
    id = "vllm"
    nombre = "vLLM"
    puertos_defecto = (PUERTO_DEFECTO,)
    enlace_defecto = "todas"        # sin --host escucha en todas las interfaces IPv4
    opciones = OPCIONES
    variables = VARIABLES
    variables_clave = ("VLLM_API_KEY",)
    post_permitidos = frozenset()
    fichero_cve = "cve_vllm.json"
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
    def _ids_propios(modelos):
        """Identificadores de `/v1/models` con `owned_by: vllm`."""
        datos = modelos.json() if modelos.estado == 200 else None
        lista = datos.get("data") if isinstance(datos, dict) else None
        if not isinstance(lista, list):
            return []
        return [d.get("id") for d in lista if isinstance(d, dict) and d.get("owned_by") == "vllm"]

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
        ids = self._ids_propios(modelos)
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
