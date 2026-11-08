"""
Perfil de llama.cpp (`llama-server`). Datos comprobados contra la build b11583.

La cabecera `Server: llama.cpp` aparece en todas las respuestas, también en 401 y 404, y
basta para reconocer el producto. `/health`, `/props`, `/build.json`, `/v1/models`, `/tools`
y una ruta inexistente no tocan la cola de tareas ni despiertan un servidor dormido.

El sondeo lee primero los indicadores de `/props` para no tener que pedir lo que tiene efectos:
`GET /metrics` pone a cero dos indicadores, y `GET /slots`, `GET /lora-adapters` y
`POST /slots/...` despiertan un servidor dormido y recargan el modelo.
"""
from __future__ import annotations

import secrets

from mrrobotia import cve
from mrrobotia.nucleo import Hallazgo, Severidad
from mrrobotia.perfiles.base import (
    MAX_MODELOS, MODULO_ARRANQUE, MODULO_EXPOSICION, REFS_EXPO, REFS_FUGA, REFS_MODELS, REFS_SECRETOS,
    REFS_SUPPLY, Identificacion, Op, Perfil, es_ruta_absoluta, hallazgo_autenticacion, hallazgo_modelos,
    ids_modelos, limpiar, nombre_fichero, nombre_modelo, normalizar_prefijo, version_segura,
)
from mrrobotia.red import a_puerto, clasificar_direccion, es_no_loopback

# POST sin cuerpo que distingue si hay --slot-save-path (400) o no (501) y no guarda nada.
RUTA_ACCION_NULA = "/slots/0?action=mrrobotia-noop"
# Desde esta build, /v1/models exige la clave; antes era pública.
BUILD_MODELOS_CON_CLAVE = 10518
_HERRAMIENTAS_CRITICAS = {"all", "exec_shell_command", "write_file", "edit_file"}


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


# ----------------------------------------------- sondeo de red: una función por hallazgo
def _h(id_, titulo, severidad, evidencia, recomendacion, refs=REFS_EXPO, estado="confirmado"):
    return Hallazgo(MODULO_EXPOSICION, id_, titulo, severidad, estado, evidencia, recomendacion, refs)


def _graduar(expuesto, en_loopback, en_red):
    return en_red if expuesto else en_loopback


def _hallazgo_props(datos, expuesto):
    """`/props` abierto. La ruta del modelo y la plantilla nunca pasan a la evidencia: de la
    primera, el nombre del fichero; de la segunda, su longitud."""
    severidad = _graduar(expuesto, Severidad.MEDIA, Severidad.ALTA)
    plantilla = datos.get("chat_template")
    extra = f"; chat_template de {len(plantilla)} caracteres" if isinstance(plantilla, str) and plantilla else ""
    consejo = ("Exige clave de API o restringe /props: revela los parámetros del servidor y una plantilla "
               "de chat que puede incluir el system prompt (LLM02).")
    ruta = datos.get("model_path")
    if es_ruta_absoluta(ruta):
        return _h("H2-PROPS", "El endpoint /props revela la ruta del modelo cargado", severidad,
                  f"/props accesible; model_path es una ruta absoluta (fichero {nombre_modelo(ruta)}){extra}",
                  consejo + " --alias no oculta esta ruta.", REFS_FUGA)
    return _h("H2-PROPS", "El endpoint /props está accesible", severidad,
              f"/props accesible, sin ruta de modelo{extra}", consejo, REFS_FUGA)


def _hay_contenido(valor):
    return bool(valor.strip()) if isinstance(valor, str) else valor not in (None, [], {})


def _analizar_slots(datos):
    """(número de slots, ¿hay texto de prompts?, ¿se ve qué adaptador usa cada petición?).
    Nunca devuelve el texto."""
    slots = datos.get("slots") if isinstance(datos, dict) else datos
    if not isinstance(slots, list):
        return 0, False, False
    filas = [s for s in slots if isinstance(s, dict)]
    hay_prompt = any(_hay_contenido(s.get(campo)) for s in filas for campo in ("prompt", "generated"))
    hay_lora = any(isinstance(s.get("params"), dict) and s["params"].get("lora") for s in filas)
    return len(slots), hay_prompt, hay_lora


def _hallazgo_slots(cliente, datos, dormido, expuesto):
    """`/slots`, graduado según publique o no el texto de los prompts. Por defecto no lo
    publica: eso solo ocurre con LLAMA_SERVER_SLOTS_DEBUG."""
    if datos.get("endpoint_slots") is False:
        return None
    if dormido:
        if datos.get("endpoint_slots") is not True:
            return None
        return _h("H2-SLOTS", "El endpoint /slots está activo (sin comprobar su contenido)",
                  _graduar(expuesto, Severidad.BAJA, Severidad.MEDIA),
                  "/props indica endpoint_slots; no se pide con el servidor dormido para no despertarlo",
                  "Arranca con --no-slots o exige clave de API.", REFS_FUGA, "potencial")
    respuesta = cliente.get("/slots")
    if respuesta.estado is None:
        return _h("H2-SLOTS", "No se pudo comprobar /slots", Severidad.INFO,
                  f"sin respuesta ({respuesta.error}); esto no demuestra que esté protegido",
                  "Comprueba /slots a mano.", REFS_FUGA, "informativo")
    if respuesta.estado != 200:
        return None
    n_slots, hay_prompt, hay_lora = _analizar_slots(respuesta.json())
    evidencia = f"/slots accesible, {n_slots} slot(s)"
    if hay_lora:
        evidencia += "; muestra qué adaptador usa cada petición"
    if hay_prompt:
        return _h("H2-SLOTS", "El endpoint /slots publica el texto de las conversaciones",
                  _graduar(expuesto, Severidad.ALTA, Severidad.CRITICA),
                  evidencia + " (campos prompt o generated con contenido)",
                  "Retira LLAMA_SERVER_SLOTS_DEBUG del entorno del servidor: hace que /slots incluya prompts y "
                  "respuestas. Exige además clave de API o arranca con --no-slots (A5/LLM02).", REFS_FUGA)
    return _h("H2-SLOTS", "El endpoint /slots expone el estado de los slots, sin texto de prompts",
              _graduar(expuesto, Severidad.BAJA, Severidad.MEDIA), evidencia,
              "Arranca con --no-slots o exige clave de API: aun sin texto revela actividad y longitud de "
              "los prompts (LLM02).", REFS_FUGA)


def _hallazgo_lora(cliente, expuesto):
    """Adaptadores cargados. Cualquier cliente con acceso a la API puede activar cualquiera
    de ellos solo para su petición: si guardan conocimiento por perfil, no hay separación."""
    respuesta = cliente.get("/lora-adapters")
    lista = respuesta.json() if respuesta.estado == 200 else None
    if not isinstance(lista, list) or not lista:
        return None
    con_ruta = sum(1 for a in lista if isinstance(a, dict) and es_ruta_absoluta(a.get("path")))
    return _h("H2-LORA", "Cualquier cliente puede usar los adaptadores LoRA cargados",
              _graduar(expuesto, Severidad.MEDIA, Severidad.ALTA),
              f"/lora-adapters accesible, {len(lista)} adaptador(es), {con_ruta} con ruta absoluta",
              "Si los adaptadores guardan conocimiento restringido, no expongas llama-server directamente: "
              "ponlo tras un control de acceso que decida qué adaptador usa cada usuario (LLM02).", REFS_FUGA)


def _hallazgo_guardado_slots(cliente):
    """--slot-save-path, con la única POST permitida: acción inexistente y sin cuerpo."""
    respuesta = cliente.post_inocuo(RUTA_ACCION_NULA)
    if respuesta.estado != 400 or "invalid action" not in respuesta.texto().lower():
        return None
    return _h("H2-SLOT-SAVE", "Cualquiera puede guardar y restaurar el estado de los slots", Severidad.ALTA,
              "POST /slots/0 con una acción inexistente responde 400 Invalid action: --slot-save-path está activo",
              "Exige clave de API o retira --slot-save-path: escribe en disco los tokens de las conversaciones y "
              "restaurarlos es superficie de ataque conocida (A5).", REFS_FUGA)


def _hallazgo_cors_proxy(cliente, datos):
    """Reenvío a URL arbitrarias (SSRF). Se lee de `/props`; sin el indicador, se prueba
    `/cors-proxy` sin `url`, que responde 403 si está desactivado y 500 si está activo."""
    activo = datos.get("cors_proxy_enabled")
    if activo is None:
        respuesta = cliente.get("/cors-proxy")
        activo = respuesta.estado == 500 and "no scheme" in respuesta.texto()
    if activo is not True:
        return None
    return _h("H2-CORS-PROXY", "El proxy /cors-proxy está activo y sin clave", Severidad.CRITICA,
              "/props indica cors_proxy_enabled o /cors-proxy sin url responde como activo",
              "Retira --ui-mcp-proxy o --agent, o exige clave de API: permite enviar peticiones a cualquier URL "
              "desde el servidor (SSRF).")


def _hallazgo_herramientas(cliente):
    """`GET /tools` solo lee la lista; ejecutar una herramienta sería POST y nunca se hace."""
    respuesta = cliente.get("/tools")
    lista = respuesta.json() if respuesta.estado == 200 else None
    if not isinstance(lista, list) or not lista:
        return None
    filas = [t for t in lista if isinstance(t, dict)]
    nombres = [limpiar(t.get("tool") or "?", 40) for t in filas]
    escritura = sum(1 for t in filas if isinstance(t.get("permissions"), dict) and t["permissions"].get("write"))
    grave = escritura or _HERRAMIENTAS_CRITICAS & set(nombres)
    return _h("H2-TOOLS", "Las herramientas del servidor están accesibles sin clave",
              Severidad.CRITICA if grave else Severidad.ALTA,
              f"{len(filas)} herramienta(s), {escritura} con permiso de escritura: " + ", ".join(nombres[:MAX_MODELOS]),
              "Retira --tools y --agent, o exige clave de API: un cliente puede hacer que el servidor las ejecute. "
              "Si las necesitas, aíslalas con --tools-runtime (A5).")


def _hallazgo_metricas(datos, expuesto):
    """Solo se lee el indicador: pedir `/metrics` pondría a cero dos indicadores de Prometheus."""
    if datos.get("endpoint_metrics") is not True:
        return None
    return _h("H2-METRICS", "El endpoint /metrics (Prometheus) está accesible",
              _graduar(expuesto, Severidad.BAJA, Severidad.MEDIA),
              "/props indica endpoint_metrics; no se pide para no alterar sus contadores",
              "Restringe /metrics o exige clave de API: expone métricas de uso útiles para perfilar el servicio (A5).")


def _hallazgo_props_escritura(datos):
    if datos.get("endpoint_props") is not True:
        return None
    return _h("H2-PROPS-ESCRITURA", "POST /props está habilitado", Severidad.BAJA,
              "/props indica endpoint_props", "Si no lo necesitas, retira --props.")


def _hallazgo_router(datos, expuesto):
    """Modo router sin clave: cualquiera puede cargar, descargar o borrar modelos."""
    instancias = datos.get("max_instances")
    return _h("H2-ROUTER", "Servidor en modo router sin clave", _graduar(expuesto, Severidad.MEDIA, Severidad.ALTA),
              f"/props con role=router; max_instances={instancias if isinstance(instancias, int) else '?'}",
              "Exige clave de API: sin ella, quien alcance el puerto puede cargar, descargar y borrar modelos (A5).")


def _hallazgo_lista_modelos(cliente, servidor, autenticacion, expuesto):
    """`/v1/models`. En modo router, `id` es un alias pero `status` publica la orden de arranque."""
    respuesta = cliente.get("/v1/models")
    datos = respuesta.json() if respuesta.estado == 200 else None
    if not isinstance(datos, dict):
        return None
    lista = datos.get("data") if isinstance(datos.get("data"), list) else []
    estados = [d.get("status") for d in lista if isinstance(d, dict)]
    con_orden = sum(1 for e in estados if isinstance(e, dict) and (e.get("args") or e.get("preset")))
    if con_orden:
        return _h("H2-MODELS", "El endpoint /v1/models publica cómo se arrancan los modelos",
                  _graduar(expuesto, Severidad.MEDIA, Severidad.ALTA),
                  f"{len(lista)} modelo(s); status.args o status.preset presentes en {con_orden}",
                  "Exige clave de API: la orden de arranque incluye rutas de disco y parámetros (LLM02).", REFS_MODELS)
    hallazgo = hallazgo_modelos(ids_modelos(datos))
    if hallazgo is not None and autenticacion == "activa":
        build = cve.clave_build(servidor.version)
        if build is None or build < BUILD_MODELOS_CON_CLAVE:
            hallazgo.evidencia += f"; es pública aun con clave en las builds anteriores a b{BUILD_MODELOS_CON_CLAVE}"
    return hallazgo


def _hallazgo_webui(cliente, datos, autenticacion, expuesto):
    """Interfaz web en `/`. Sin `Accept-Encoding: gzip`, llama-server responde 415."""
    if datos.get("ui") is False:
        return None
    respuesta = cliente.get("/", gzip=True)
    if respuesta.estado != 200:
        return None
    tipo = str(respuesta.cabeceras.get("content-type", "")).lower()
    if "text/html" not in tipo and "<html" not in respuesta.texto().lower():
        return None
    if autenticacion == "abierta":
        detalle = "sin clave, ofrece una consola de chat contra el modelo a quien alcance el puerto (A5)."
    else:
        detalle = "la página se sirve también sin clave, aunque el uso del modelo dependa de la API (A5)."
    return _h("H2-WEBUI", "La interfaz web integrada de llama-server está accesible",
              _graduar(expuesto, Severidad.BAJA, Severidad.MEDIA), "respuesta 200 HTML en '/'",
              "Si no usas la interfaz web, arranca con --no-webui; " + detalle)


def _detalle_autenticacion(props, autenticacion, servidor):
    """Qué se ha pedido, qué ha respondido y, si no concluye, por qué puede ser."""
    estado = props.estado if props.estado is not None else "sin respuesta"
    detalle = f"GET /props sin credenciales: {estado}"
    if props.estado == 404:
        detalle += " (puede usar un prefijo --api-prefix desconocido)"
    elif props.estado == 503:
        detalle += " (está cargando el modelo)"
    if autenticacion == "indeterminada" and servidor.autenticacion == "activa":
        detalle += "; el arranque configura una clave"
    return detalle


# -------------------------------------------------- arranque: `llamacpp.md` §7
_VALORES_FALSOS = {"off", "disabled", "false", "0", ""}
_OPCIONES_INFORMATIVAS = (
    "port", "api_prefix", "cors_methods", "cors_headers", "tools_runtime", "lora_init_without_apply",
    "sleep_idle_seconds", "timeout", "threads_http", "parallel", "ctx_size", "cache_ram",
)
_OPCIONES_DESCARGA = (("-mu", "model_url", "LLAMA_ARG_MODEL_URL"), ("-mmu", "mmproj_url", "LLAMA_ARG_MMPROJ_URL"),
                      ("-hf", "hf_repo", "LLAMA_ARG_HF_REPO"), ("-dr", "docker_repo", "LLAMA_ARG_DOCKER_REPO"))
# Avisos que solo aplican si el servidor se arrancó con cierta opción.
_OPCION_DE_AVISO = {"CVE-2026-43631": "sleep_idle_seconds", "CVE-2026-43632": "sleep_idle_seconds",
                    "CVE-2026-52132": "reranking"}
_OPCION_DE_COMPONENTE = {"rpc": "rpc", "slot-restore": "slot_save_path"}
_VARIABLE_DE_OPCION = {"rpc": "LLAMA_ARG_RPC", "slot_save_path": "LLAMA_ARG_SLOT_SAVE_PATH"}


def _a(id_, titulo, severidad, evidencia, recomendacion, refs=REFS_EXPO, estado="confirmado"):
    return Hallazgo(MODULO_ARRANQUE, f"H2-ARRANQUE-{id_}", titulo, severidad, estado, evidencia, recomendacion, refs)


def _valor(servidor, clave, variable=None):
    """Valor de una opción o, si no consta, de su variable de entorno. None si no consta."""
    if clave in servidor.opciones:
        return servidor.opciones[clave]
    return servidor.entorno.get(variable) if variable else None


def _activada(servidor, clave, variable=None, defecto=False):
    """¿Está activada una bandera? Sin dato, su valor por defecto."""
    valor = _valor(servidor, clave, variable)
    if valor is None:
        return defecto
    return valor if isinstance(valor, bool) else str(valor).strip().lower() not in _VALORES_FALSOS


def _consta(servidor, clave, variable=None):
    return _valor(servidor, clave, variable) is not None


def _arranque_enlace(s, con_clave):
    host = _valor(s, "host", "LLAMA_ARG_HOST")
    if not isinstance(host, str) or host.endswith(".sock"):
        return None
    if not any(es_no_loopback(clasificar_direccion(p)) for p in host.split(",")):
        return None
    return _a("HOST", "Arrancado para escuchar fuera de loopback", Severidad.ALTA if con_clave else Severidad.CRITICA,
              f"--host {limpiar(host)}" + ("" if con_clave else "; no consta clave de API"),
              "Usa --host 127.0.0.1 y pon delante un proxy con autenticación si necesitas acceso remoto (A5).")


def _arranque_clave(s, expuesto, con_clave):
    filas = []
    if s.opciones.get("api_key") is True:
        filas.append(_a(
            "CLAVE-EN-ORDEN", "La clave de API está en la línea de órdenes", Severidad.MEDIA,
            "--api-key presente en la línea de órdenes (no se conserva su valor)",
            "Usa --api-key-file o LLAMA_API_KEY: la línea de órdenes de un proceso la pueden leer otros "
            "usuarios del equipo y queda en los registros.", REFS_SECRETOS))
    if not con_clave:
        abierta = s.autenticacion == "abierta"
        filas.append(_a(
            "SIN-CLAVE", "El servidor arranca sin clave de API", _graduar(expuesto, Severidad.MEDIA, Severidad.CRITICA),
            "no consta --api-key, --api-key-file ni LLAMA_API_KEY"
            + ("; responde sin credenciales" if abierta else "; podría venir del entorno, que no siempre es legible"),
            "Arranca con --api-key-file o define LLAMA_API_KEY (A5).", estado="confirmado" if abierta else "potencial"))
    return filas


def _arranque_tls(s, expuesto):
    if _consta(s, "ssl_cert_file", "LLAMA_ARG_SSL_CERT_FILE") or _consta(s, "ssl_key_file", "LLAMA_ARG_SSL_KEY_FILE"):
        return None
    return _a("TLS", "El servidor arranca sin TLS", _graduar(expuesto, Severidad.BAJA, Severidad.ALTA),
              "no consta --ssl-cert-file ni --ssl-key-file",
              "Usa --ssl-key-file y --ssl-cert-file, o un proxy inverso con HTTPS, si el tráfico sale del equipo.",
              estado="confirmado" if s.esquema == "http" and "http" in s.fuentes else "potencial")


def _arranque_cors(s, con_clave):
    origenes = _valor(s, "cors_origins", "LLAMA_ARG_CORS_ORIGINS")
    if origenes is True:
        return None
    # Con herramientas o MCP, el valor por defecto pasa a ser «solo localhost».
    if origenes is None and (_consta(s, "tools", "LLAMA_ARG_TOOLS") or _activada(s, "agent", "LLAMA_ARG_AGENT")
                             or _consta(s, "mcp_servers_config", "LLAMA_ARG_MCP_SERVERS_CONFIG")
                             or _consta(s, "mcp_servers_json", "LLAMA_ARG_MCP_SERVERS_JSON")):
        return None
    texto = limpiar(origenes) if origenes is not None else "*"
    if "," in str(origenes):
        return _a("CORS", "--cors-origins contiene una lista que los navegadores no aceptan", Severidad.BAJA,
                  f"--cors-origins {texto}",
                  "llama-server envía la lista tal cual en la cabecera y ningún navegador la acepta: "
                  "usa un único origen.")
    if origenes not in (None, "*"):
        return None
    credenciales = _activada(s, "cors_credentials", "LLAMA_ARG_CORS_CREDENTIALS", defecto=True)
    if not con_clave:
        severidad = Severidad.ALTA
    else:
        severidad = Severidad.MEDIA if credenciales else Severidad.BAJA
    return _a("CORS", "CORS permite cualquier origen", severidad,
              f"cors_origins={texto}, credenciales={'sí' if credenciales else 'no'}"
              + ("" if origenes is not None else " (valor por defecto)"),
              "Fija --cors-origins al origen de tu aplicación o a localhost: cualquier web podría leer las "
              "respuestas desde el navegador de la víctima (A5).",
              estado="confirmado" if origenes is not None else "potencial")


def _arranque_web(s, expuesto, con_clave):
    filas = []
    if _activada(s, "webui", "LLAMA_ARG_UI", defecto=True):
        filas.append(_a("WEBUI", "La interfaz web está activa", _graduar(expuesto, Severidad.BAJA, Severidad.MEDIA),
                        "no consta --no-webui" if not _consta(s, "webui", "LLAMA_ARG_UI") else "interfaz web activada",
                        "Si no la usas, arranca con --no-webui.",
                        estado="confirmado" if _consta(s, "webui", "LLAMA_ARG_UI") else "potencial"))
    if _consta(s, "ui_config", "LLAMA_ARG_UI_CONFIG") or _consta(s, "ui_config_file", "LLAMA_ARG_UI_CONFIG_FILE"):
        filas.append(_a("UI-CONFIG", "Configuración propia de la interfaz web", Severidad.BAJA,
                        "--ui-config o --ui-config-file presente",
                        "Es visible en /props.ui_settings: no pongas ahí datos sensibles.", REFS_FUGA))
    if _activada(s, "ui_mcp_proxy", "LLAMA_ARG_UI_MCP_PROXY"):
        filas.append(_a("MCP-PROXY", "Proxy MCP de la interfaz activado",
                        Severidad.CRITICA if expuesto or not con_clave else Severidad.ALTA,
                        "--ui-mcp-proxy presente; permite peticiones a URL arbitrarias (SSRF)",
                        "Retíralo si no lo necesitas y exige clave de API."))
    if _activada(s, "agent", "LLAMA_ARG_AGENT"):
        filas.append(_a("AGENTE", "Modo agente activado", Severidad.CRITICA,
                        "--agent presente; habilita todas las herramientas y el proxy",
                        "No lo uses en un servidor accesible: un cliente puede leer, escribir y ejecutar en el equipo."))
    herramientas = _valor(s, "tools", "LLAMA_ARG_TOOLS")
    if herramientas:
        nombres = {n.strip() for n in str(herramientas).split(",")}
        filas.append(_a("TOOLS", "Herramientas del servidor activadas",
                        Severidad.CRITICA if nombres & _HERRAMIENTAS_CRITICAS else Severidad.ALTA,
                        f"--tools {limpiar(herramientas)}",
                        "Limita las herramientas a las de solo lectura y aíslalas con --tools-runtime."))
    if (_consta(s, "mcp_servers_config", "LLAMA_ARG_MCP_SERVERS_CONFIG")
            or _consta(s, "mcp_servers_json", "LLAMA_ARG_MCP_SERVERS_JSON")):
        filas.append(_a("MCP", "Servidores MCP configurados", Severidad.ALTA,
                        "--mcp-servers-config o --mcp-servers-json presente (no se conserva su contenido)",
                        "Revisa qué permiten esos servidores: el modelo podrá invocarlos."))
    return filas


def _arranque_rutas(s, expuesto, con_clave):
    filas = []
    if _activada(s, "metrics", "LLAMA_ARG_ENDPOINT_METRICS"):
        filas.append(_a("METRICS", "/metrics activado", _graduar(expuesto, Severidad.BAJA, Severidad.MEDIA),
                        "--metrics presente", "Si no lo usas, retíralo; si lo usas, restríngelo tras autenticación."))
    if _activada(s, "props", "LLAMA_ARG_ENDPOINT_PROPS"):
        filas.append(_a("PROPS", "POST /props activado", Severidad.BAJA, "--props presente",
                        "Si no lo necesitas, retíralo."))
    if _activada(s, "slots", "LLAMA_ARG_ENDPOINT_SLOTS", defecto=True):
        declarado = _consta(s, "slots", "LLAMA_ARG_ENDPOINT_SLOTS")
        filas.append(_a("SLOTS", "/slots está activo", _graduar(expuesto, Severidad.BAJA, Severidad.MEDIA),
                        "activado" if declarado else "no consta --no-slots: está activo por defecto",
                        "Arranca con --no-slots si no lo necesitas.", REFS_FUGA,
                        estado="confirmado" if declarado else "potencial"))
    depuracion = s.entorno.get("LLAMA_SERVER_SLOTS_DEBUG")
    if depuracion is not None and str(depuracion).strip() != "0":
        filas.append(_a("SLOTS-DEBUG", "/slots publica el texto de los prompts",
                        _graduar(expuesto, Severidad.ALTA, Severidad.CRITICA),
                        "LLAMA_SERVER_SLOTS_DEBUG definida y distinta de 0",
                        "Retira esa variable del entorno del servidor.", REFS_FUGA))
    if _consta(s, "slot_save_path", "LLAMA_ARG_SLOT_SAVE_PATH"):
        filas.append(_a("SLOT-SAVE", "Guardado de slots en disco activado",
                        Severidad.MEDIA if con_clave else Severidad.ALTA, "--slot-save-path presente",
                        "Las conversaciones quedan en disco: retíralo si no lo necesitas.", REFS_FUGA))
    if _consta(s, "media_path"):
        filas.append(_a("MEDIA-PATH", "Lectura de ficheros locales por file:// activada", Severidad.MEDIA,
                        "--media-path presente", "Limita ese directorio a lo imprescindible."))
    if _consta(s, "path", "LLAMA_ARG_STATIC_PATH"):
        filas.append(_a("STATIC-PATH", "Sirve ficheros estáticos de un directorio", Severidad.MEDIA,
                        "--path presente", "Comprueba que ese directorio no contenga nada sensible."))
    return filas


def _arranque_registros(s):
    filas = []
    if _consta(s, "log_prompts_dir"):
        filas.append(_a("LOG-PROMPTS", "Cada prompt se escribe en claro en disco", Severidad.ALTA,
                        "--log-prompts-dir presente", "Retíralo fuera de una depuración puntual.", REFS_FUGA))
    verbosidad = _valor(s, "log_verbosity", "LLAMA_ARG_LOG_VERBOSITY")
    if s.opciones.get("verbose") is True or (str(verbosidad).isdigit() and int(verbosidad) >= 5):
        filas.append(_a("LOG-VERBOSIDAD", "Registro en modo depuración", Severidad.MEDIA,
                        "verbosidad de depuración activada",
                        "A ese nivel, el registro incluye el contenido de los prompts.", REFS_FUGA))
    if _consta(s, "log_file", "LLAMA_ARG_LOG_FILE"):
        filas.append(_a("LOG-FILE", "El registro se guarda en un fichero", Severidad.BAJA,
                        "--log-file presente", "Protege ese fichero y define su retención.", REFS_FUGA))
    return filas


def _arranque_modelos(s, expuesto):
    filas = []
    if _consta(s, "rpc", "LLAMA_ARG_RPC"):
        filas.append(_a("RPC", "Backend RPC configurado", Severidad.ALTA, "--rpc presente",
                        "El protocolo RPC no tiene autenticación y acumula avisos publicados: úsalo solo en una "
                        "red aislada.", REFS_SUPPLY))
    if _consta(s, "lora") or _consta(s, "lora_scaled"):
        filas.append(_a("LORA", "Adaptadores LoRA cargados al arrancar", Severidad.INFO,
                        "--lora o --lora-scaled presente",
                        "Si guardan conocimiento por perfil, cualquier cliente de la API puede activarlos: hace falta "
                        "un control de acceso delante.", REFS_FUGA, "informativo"))
    if _consta(s, "models_dir", "LLAMA_ARG_MODELS_DIR") or _consta(s, "models_preset", "LLAMA_ARG_MODELS_PRESET"):
        filas.append(_a("ROUTER", "Modo router configurado", _graduar(expuesto, Severidad.INFO, Severidad.ALTA),
                        "--models-dir o --models-preset presente",
                        "No lo expongas: permite cargar, descargar y borrar modelos.",
                        estado="confirmado" if expuesto else "informativo"))
    if s.opciones.get("hf_token") is True:
        filas.append(_a("HF-TOKEN", "Token de Hugging Face en la línea de órdenes", Severidad.MEDIA,
                        "--hf-token presente (no se conserva su valor)",
                        "Usa la variable HF_TOKEN o un gestor de secretos.", REFS_SECRETOS))
    descargas = [etiqueta for etiqueta, clave, variable in _OPCIONES_DESCARGA if _consta(s, clave, variable)]
    if descargas:
        filas.append(_a("DESCARGA", "Modelo descargado al arrancar", Severidad.BAJA,
                        "origen remoto: " + ", ".join(descargas),
                        "Fija la revisión y verifica su hash: cada arranque depende de un origen externo.", REFS_SUPPLY))
    if _activada(s, "reuse_port", "LLAMA_ARG_REUSE_PORT"):
        filas.append(_a("REUSE-PORT", "--reuse-port activado", Severidad.BAJA, "--reuse-port presente",
                        "Otro proceso del mismo usuario podría escuchar en ese puerto y recibir parte del tráfico."))
    return filas


def _arranque_informativas(s):
    """Las opciones sin riesgo propio se resumen en un único hallazgo."""
    vistas = [f"{clave}={limpiar(s.opciones[clave], 40)}" for clave in _OPCIONES_INFORMATIVAS if clave in s.opciones]
    if not vistas:
        return None
    recomendacion = ""
    if s.opciones.get("sleep_idle_seconds") not in (None, "-1"):
        recomendacion = "--sleep-idle-seconds: revisa CVE-2026-43631 y CVE-2026-43632 (H2-CVE)."
    return _a("OTRAS", "Otras opciones de arranque, sin riesgo propio", Severidad.INFO, ", ".join(vistas),
              recomendacion, estado="informativo")


class LlamaCpp(Perfil):
    id = "llama.cpp"
    nombre = "llama.cpp"
    # 9931 es el puerto por defecto de las builds recientes; 8080, el de las anteriores.
    puertos_defecto = (9931, 8080)
    enlace_defecto = "loopback"
    opciones = OPCIONES
    variables = VARIABLES
    variables_clave = ("LLAMA_API_KEY", "LLAMA_ARG_API_KEY_FILE")
    post_permitidos = frozenset({RUTA_ACCION_NULA})
    fichero_cve = "cve_llamacpp.json"
    clave_version = staticmethod(cve.clave_build)

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

    # --------------------------------------------- comprobaciones por servidor
    def sondear(self, cliente, servidor, expuesto, proxy) -> list:
        """Lo específico de llama-server. Solo GET y la POST sin efecto de la lista blanca.
        Sin `/props` abierto no hay indicadores: lo demás quedaría tras la clave."""
        props = cliente.get("/props")
        autenticacion = self._autenticacion(cliente, props)
        detalle = _detalle_autenticacion(props, autenticacion, servidor)
        if autenticacion != "indeterminada":        # lo no concluyente no borra lo que dice el arranque
            servidor.autenticacion = autenticacion
        datos = props.json() if props.estado == 200 else None
        datos = datos if isinstance(datos, dict) else {}
        hallazgos = [
            hallazgo_autenticacion(autenticacion, detalle, expuesto, proxy,
                                   "Arranca llama-server con --api-key-file, o ponlo tras un proxy que autentique"),
            self._hallazgo_build(cliente, servidor, datos),
        ]
        if props.estado == 200:
            hallazgos.extend(self._sondear_abierto(cliente, datos, expuesto))
        hallazgos.append(_hallazgo_lista_modelos(cliente, servidor, autenticacion, expuesto))
        hallazgos.append(_hallazgo_webui(cliente, datos, autenticacion, expuesto))
        return [h for h in hallazgos if h is not None]

    @staticmethod
    def _sondear_abierto(cliente, datos, expuesto):
        """Con `/props` abierto. Dormido no se pide lo que despierta el servidor, y en modo
        router esas rutas no valen: exigen indicar un modelo."""
        dormido, router = datos.get("is_sleeping") is True, datos.get("role") == "router"
        hallazgos = [_hallazgo_props(datos, expuesto), _hallazgo_metricas(datos, expuesto),
                     _hallazgo_props_escritura(datos), _hallazgo_cors_proxy(cliente, datos),
                     _hallazgo_herramientas(cliente)]
        if router:
            hallazgos.append(_hallazgo_router(datos, expuesto))
        else:
            hallazgos.append(_hallazgo_slots(cliente, datos, dormido, expuesto))
            if not dormido:
                hallazgos += [_hallazgo_lora(cliente, expuesto), _hallazgo_guardado_slots(cliente)]
        return hallazgos

    @staticmethod
    def _hallazgo_build(cliente, servidor, datos):
        """Build, de `/props` o, sin él, de `/build.json`, que es público aun con clave."""
        version = version_segura(datos.get("build_info"))
        publica = False
        if version is None:
            build = cliente.get("/build.json", gzip=True)
            datos_build = build.json() if build.estado == 200 else None
            version = version_segura(datos_build.get("version")) if isinstance(datos_build, dict) else None
            publica = version is not None
        servidor.version = version or servidor.version
        evidencia = f"build = {servidor.version or 'desconocida'}"
        return _h("H2-BUILD", "Build de llama.cpp/llama-server detectada", Severidad.INFO,
                  evidencia + ("; /build.json la publica sin clave" if publica else ""), "", REFS_SUPPLY, "informativo")

    def evaluar_arranque(self, servidor, expuesto) -> list:
        """Riesgos de cómo se arrancó (`llamacpp.md` §7). Lo que falta en la línea de órdenes
        queda como `potencial` salvo que la red lo confirme: la opción puede venir del entorno,
        que en Windows no es legible. Solo presencia o valores saneados."""
        con_clave = servidor.autenticacion == "activa"
        filas = [_arranque_enlace(servidor, con_clave), *_arranque_clave(servidor, expuesto, con_clave),
                 _arranque_tls(servidor, expuesto), _arranque_cors(servidor, con_clave),
                 *_arranque_web(servidor, expuesto, con_clave), *_arranque_rutas(servidor, expuesto, con_clave),
                 *_arranque_registros(servidor), *_arranque_modelos(servidor, expuesto),
                 _arranque_informativas(servidor)]
        return [h for h in filas if h is not None]

    def componente_en_uso(self, aviso, servidor):
        componente = cve.componente(aviso)
        if componente == "android-jni":
            return False                # solo afecta al envoltorio de Android
        if componente == "mtmd":
            return None                 # no consta si hay un mmproj cargado
        opcion = _OPCION_DE_AVISO.get(aviso.get("id")) or _OPCION_DE_COMPONENTE.get(componente)
        if opcion is None:
            return True
        if not servidor.opciones and not servidor.entorno:
            return None                 # no se sabe cómo se arrancó
        return _valor(servidor, opcion, _VARIABLE_DE_OPCION.get(opcion)) not in (None, False, "-1")
