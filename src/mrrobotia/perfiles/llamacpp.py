"""
Perfil de llama.cpp (`llama-server`). Datos comprobados contra la build b11583.

La cabecera `Server: llama.cpp` aparece en todas las respuestas, también en 401 y 404, y
basta para reconocer el producto. `/health`, `/props`, `/build.json` y una ruta inexistente
no tocan la cola de tareas ni despiertan un servidor dormido.
"""
from __future__ import annotations

import secrets

from mrrobotia.perfiles.base import (
    Identificacion, Op, Perfil, nombre_fichero, nombre_modelo, normalizar_prefijo, version_segura,
)
from mrrobotia.red import a_puerto


def _bandera(clave, positivas, negativas):
    """Entradas de una bandera booleana con sus formas de activar y desactivar."""
    tabla = {f: Op(clave, valor=False, fija=True) for f in positivas}
    tabla.update({f: Op(clave, valor=False, fija=False) for f in negativas})
    return tabla


OPCIONES = {
    # Red y transporte. --host admite sockets UNIX: de ellos solo se guarda el nombre.
    "--host": Op("host", es_ruta=True),
    "--port": Op("port"),
    "--api-prefix": Op("api_prefix"),
    "--path": Op("path", es_ruta=True),
    "--ssl-key-file": Op("ssl_key_file", es_ruta=True),
    "--ssl-cert-file": Op("ssl_cert_file", es_ruta=True),
    **_bandera("reuse_port", ["--reuse-port"], []),
    # Autenticación y CORS
    "--api-key": Op("api_key", secreto=True),
    "--api-key-file": Op("api_key_file", es_ruta=True),
    "--cors-origins": Op("cors_origins"),
    "--cors-methods": Op("cors_methods"),
    "--cors-headers": Op("cors_headers"),
    **_bandera("cors_credentials", ["--cors-credentials"], ["--no-cors-credentials"]),
    # Interfaz web y herramientas
    **_bandera("webui", ["--ui", "--webui"], ["--no-ui", "--no-webui"]),
    "--ui-config": Op("ui_config", secreto=True),
    "--webui-config": Op("ui_config", secreto=True),
    "--ui-config-file": Op("ui_config_file", es_ruta=True),
    "--webui-config-file": Op("ui_config_file", es_ruta=True),
    **_bandera("ui_mcp_proxy", ["--ui-mcp-proxy", "--webui-mcp-proxy"],
               ["--no-ui-mcp-proxy", "--no-webui-mcp-proxy"]),
    "--tools": Op("tools"),
    "--tools-runtime": Op("tools_runtime"),
    "--mcp-servers-config": Op("mcp_servers_config", es_ruta=True),
    "--mcp-servers-json": Op("mcp_servers_json", secreto=True),
    **_bandera("agent", ["-ag", "--agent"], ["-no-ag", "--no-agent"]),
    # Rutas de información y funciones opcionales
    **_bandera("metrics", ["--metrics"], []),
    **_bandera("props", ["--props"], []),
    **_bandera("slots", ["--slots"], ["--no-slots"]),
    **_bandera("embeddings", ["--embedding", "--embeddings"], []),
    **_bandera("reranking", ["--rerank", "--reranking"], []),
    "--slot-save-path": Op("slot_save_path", es_ruta=True),
    "--media-path": Op("media_path", es_ruta=True),
    # Registros
    "--log-prompts-dir": Op("log_prompts_dir", es_ruta=True),
    "--log-file": Op("log_file", es_ruta=True),
    "-lv": Op("log_verbosity"),
    "--verbosity": Op("log_verbosity"),
    "--log-verbosity": Op("log_verbosity"),
    **_bandera("verbose", ["-v", "--verbose", "--log-verbose"], []),
    # Modelos y adaptadores. --rpc delata la topología interna: solo presencia.
    "-m": Op("model", es_ruta=True),
    "--model": Op("model", es_ruta=True),
    "-a": Op("alias"),
    "--alias": Op("alias"),
    "--rpc": Op("rpc", secreto=True),
    "--lora": Op("lora", es_ruta=True),
    "--lora-scaled": Op("lora_scaled", es_ruta=True),
    **_bandera("lora_init_without_apply", ["--lora-init-without-apply"], []),
    "--models-dir": Op("models_dir", es_ruta=True),
    "--models-preset": Op("models_preset", es_ruta=True),
    "--models-max": Op("models_max"),
    **_bandera("models_autoload", ["--models-autoload"], ["--no-models-autoload"]),
    "--sleep-idle-seconds": Op("sleep_idle_seconds"),
    # Descargas: las URL pueden llevar credenciales
    "-hft": Op("hf_token", secreto=True),
    "--hf-token": Op("hf_token", secreto=True),
    "-mu": Op("model_url", secreto=True),
    "--model-url": Op("model_url", secreto=True),
    "-mmu": Op("mmproj_url", secreto=True),
    "--mmproj-url": Op("mmproj_url", secreto=True),
    "-hf": Op("hf_repo"),
    "-hfr": Op("hf_repo"),
    "--hf-repo": Op("hf_repo"),
    "-dr": Op("docker_repo"),
    "--docker-repo": Op("docker_repo"),
    # Límites de denegación de servicio
    "-to": Op("timeout"),
    "--timeout": Op("timeout"),
    "--threads-http": Op("threads_http"),
    "-np": Op("parallel"),
    "--parallel": Op("parallel"),
    "-c": Op("ctx_size"),
    "--ctx-size": Op("ctx_size"),
    "-cram": Op("cache_ram"),
    "--cache-ram": Op("cache_ram"),
}

# Nombre -> ¿secreta? Las variables con ruta o URL también se guardan solo como presencia.
VARIABLES = {
    "LLAMA_API_KEY": True,
    "HF_TOKEN": True,
    "LLAMA_SERVER_SLOTS_DEBUG": False,
    "LLAMA_ARG_HOST": False,
    "LLAMA_ARG_PORT": False,
    "LLAMA_ARG_API_PREFIX": False,
    "LLAMA_ARG_API_KEY_FILE": True,
    "LLAMA_ARG_SSL_KEY_FILE": True,
    "LLAMA_ARG_SSL_CERT_FILE": True,
    "LLAMA_ARG_CORS_ORIGINS": False,
    "LLAMA_ARG_CORS_CREDENTIALS": False,
    "LLAMA_ARG_CORS_METHODS": False,
    "LLAMA_ARG_CORS_HEADERS": False,
    "LLAMA_ARG_STATIC_PATH": True,
    "LLAMA_ARG_UI": False,
    "LLAMA_ARG_UI_CONFIG": True,
    "LLAMA_ARG_UI_CONFIG_FILE": True,
    "LLAMA_ARG_UI_MCP_PROXY": False,
    "LLAMA_ARG_TOOLS": False,
    "LLAMA_ARG_TOOLS_RUNTIME": False,
    "LLAMA_ARG_MCP_SERVERS_CONFIG": True,
    "LLAMA_ARG_MCP_SERVERS_JSON": True,
    "LLAMA_ARG_AGENT": False,
    "LLAMA_ARG_ENDPOINT_METRICS": False,
    "LLAMA_ARG_ENDPOINT_PROPS": False,
    "LLAMA_ARG_ENDPOINT_SLOTS": False,
    "LLAMA_ARG_SLOT_SAVE_PATH": True,
    "LLAMA_ARG_LOG_VERBOSITY": False,
    "LLAMA_ARG_LOG_FILE": True,
    "LLAMA_ARG_RPC": True,
    "LLAMA_ARG_MODELS_DIR": True,
    "LLAMA_ARG_MODELS_PRESET": True,
    "LLAMA_ARG_MODELS_MAX": False,
    "LLAMA_ARG_MODELS_AUTOLOAD": False,
    "LLAMA_ARG_MODEL_URL": True,
    "LLAMA_ARG_MMPROJ_URL": True,
    "LLAMA_ARG_HF_REPO": False,
    "LLAMA_ARG_DOCKER_REPO": False,
    "LLAMA_ARG_REUSE_PORT": False,
    "LLAMA_ARG_TIMEOUT": False,
    "LLAMA_ARG_THREADS_HTTP": False,
    "LLAMA_ARG_N_PARALLEL": False,
    "LLAMA_ARG_CTX_SIZE": False,
    "LLAMA_ARG_CACHE_RAM": False,
}


def _error_de_clave(respuesta):
    """¿Es el JSON de error de autenticación propio de llama-server?"""
    datos = respuesta.json()
    error = datos.get("error") if isinstance(datos, dict) else None
    return isinstance(error, dict) and error.get("type") == "authentication_error"


class LlamaCpp(Perfil):
    id = "llama.cpp"
    nombre = "llama.cpp"
    # 9931 es el puerto por defecto de las builds recientes; 8080, el de las anteriores.
    puertos_defecto = (9931, 8080)
    enlace_defecto = "loopback"
    opciones = OPCIONES
    variables = VARIABLES
    variables_clave = ("LLAMA_API_KEY", "LLAMA_ARG_API_KEY_FILE")
    post_permitidos = frozenset({"/slots/0?action=mrrobotia-noop"})
    fichero_cve = "cve_llamacpp.json"

    # ------------------------------------------------------------ proceso local
    def reconoce_proceso(self, argv) -> bool:
        if not argv:
            return False
        ejecutable = nombre_fichero(argv[0]).lower().removesuffix(".exe")
        if ejecutable == "llama-server":
            return True
        return ejecutable == "llama" and len(argv) > 1 and argv[1] == "serve"

    def puerto_y_host(self, opciones, entorno=None) -> tuple:
        """La opción gana a la variable, como en el propio servidor. Sin ninguna de las
        dos, el puerto queda sin determinar: el valor por defecto depende de la versión."""
        entorno = entorno or {}
        host = opciones.get("host") or entorno.get("LLAMA_ARG_HOST")
        if isinstance(host, str) and host.endswith(".sock"):
            return None, None
        return host, a_puerto(opciones.get("port") or entorno.get("LLAMA_ARG_PORT"))

    def esquema_de(self, opciones, entorno=None) -> str:
        return "https" if opciones.get("ssl_cert_file") or (entorno or {}).get("LLAMA_ARG_SSL_CERT_FILE") else "http"

    def prefijo_de(self, opciones, entorno=None) -> str:
        return normalizar_prefijo(opciones.get("api_prefix") or (entorno or {}).get("LLAMA_ARG_API_PREFIX"))

    def modelos_de(self, opciones) -> list:
        return [m for m in (opciones.get("alias"), opciones.get("model"), opciones.get("hf_repo")) if m]

    # ----------------------------------------------------------------- red
    def _autenticacion(self, cliente, props):
        """/props: 200 abierta; 401 clave, que se confirma con una ruta inexistente (401
        con clave, 404 sin ella); 404 (prefijo) y 503 (cargando) no permiten concluir."""
        if props.estado == 200:
            return "abierta"
        if props.estado in (401, 403):
            control = cliente.get(f"/mrrobotia-{secrets.token_hex(4)}")
            return "activa" if control.estado in (401, 403) else "indeterminada"
        return "indeterminada"

    def identificar_http(self, cliente) -> Identificacion | None:
        salud = cliente.get("/health")
        if salud.estado is None:
            return None
        props = cliente.get("/props")
        por_cabecera = any("llama.cpp" in str(r.cabeceras.get("server", "")).lower() for r in (salud, props))
        datos = props.json() if props.estado == 200 else None
        por_json = isinstance(datos, dict) and "build_info" in datos and "default_generation_settings" in datos
        if not por_cabecera and not por_json:
            return None

        senales = []
        if por_cabecera:
            senales.append("cabecera Server: llama.cpp")
        if por_json:
            senales.append("/props con build_info")
        version = version_segura(datos.get("build_info")) if por_json else None
        if version is None:
            build = cliente.get("/build.json", gzip=True)
            datos_build = build.json() if build.estado == 200 else None
            if isinstance(datos_build, dict):
                version = version_segura(datos_build.get("version"))
                if version:
                    senales.append("/build.json publica la versión")

        confirmado = por_json or version is not None or _error_de_clave(props)
        modelos = []
        if por_json:
            for campo in ("model_alias", "model_path"):
                nombre = nombre_modelo(datos.get(campo))
                if nombre and nombre not in modelos:
                    modelos.append(nombre)
            if datos.get("role") == "router":
                senales.append("modo router")
        return Identificacion(self.id, "alta" if confirmado else "media", version,
                              self._autenticacion(cliente, props), senales, modelos)
