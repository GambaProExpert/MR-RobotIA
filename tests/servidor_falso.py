"""Servidor HTTP falso para las pruebas: corre en un hilo y registra cada petición recibida.

Uso:
    with ServidorFalso(llamacpp(clave="k")) as s:
        cliente = ClienteHTTP(s.url)
        ...
        assert s.rutas() == [("GET", "/health"), ...]

`responder(peticion)` devuelve `(estado, cabeceras, cuerpo)`; el cuerpo es `bytes` o un
iterable de bloques que se envían uno a uno. Sirven las fábricas de este fichero o un
`desde_rutas({"GET /x": (200, {}, b"...")})`.

`llamacpp()` reproduce las capturas reales de llama-server b11583, saneadas: nombres de modelo
y claves son inventados. `vllm()` NO procede de capturas: sigue la forma que dicta el código de
vLLM 0.33.0, a falta de un servidor real con el que contrastarla.
"""
from __future__ import annotations

import gzip
import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BUILD_LLAMACPP = "b11583-988015788"
RUTA_MODELO_FALSA = "/srv/modelos/privados/modelo-falso-q4.gguf"

_JSON = "application/json; charset=utf-8"
_NO_ENCONTRADO = {"error": {"message": "File Not Found", "type": "not_found_error", "code": 404}}
_CLAVE_INVALIDA = {"error": {"message": "Invalid API Key", "type": "authentication_error", "code": 401}}
_NO_DISPONIBLE = {"error": {"code": 501, "type": "not_supported_error", "message": "x"}}
_PUBLICAS_LLAMACPP = {"/health", "/v1/health", "/", "/index.html", "/sw.js", "/manifest.webmanifest",
                      "/_app/version.json", "/build.json", "/favicon.ico"}
_PROTEGIDAS_VLLM = ("/v1", "/v2", "/inference", "/cohere")
# Rutas de vLLM que solo admiten POST: un GET responde 405 sin llegar al manejador.
_SOLO_POST_VLLM = {"/invocations", "/tokenize", "/detokenize", "/generative_scoring", "/scale_elastic_ep", "/is_scaling_elastic_ep"}
_SOLO_POST_POOLING = {"/pooling", "/classify", "/score", "/rerank"}
SOLO_POST_DESARROLLO = {
    "/collective_rpc", "/abort_requests", "/pause", "/resume", "/sleep", "/wake_up", "/release_kv_cache_memory",
    "/reset_prefix_cache", "/reset_mm_cache", "/reset_encoder_cache", "/init_weight_transfer_engine",
    "/shutdown_weight_transfer_engine", "/start_weight_update", "/start_draft_weight_update", "/update_weights",
    "/finish_weight_update", "/update_weight_version", "/weight_checker",
}


@dataclass
class Peticion:
    metodo: str
    ruta: str
    cabeceras: dict     # claves en minúsculas
    cuerpo: bytes


class _Manejador(BaseHTTPRequestHandler):
    def _atender(self):
        longitud = int(self.headers.get("Content-Length") or 0)
        cuerpo = self.rfile.read(longitud) if longitud else b""
        peticion = Peticion(self.command, self.path, {k.lower(): v for k, v in self.headers.items()}, cuerpo)
        self.server.registro.append(peticion)
        estado, cabeceras, datos = self.server.responder(peticion)
        self.send_response_only(estado)
        for nombre, valor in cabeceras.items():
            self.send_header(nombre, valor)
        if isinstance(datos, (bytes, bytearray)):
            self.send_header("Content-Length", str(len(datos)))
        self.end_headers()
        if self.command == "HEAD":
            return
        for bloque in ([datos] if isinstance(datos, (bytes, bytearray)) else datos):
            self.wfile.write(bloque)
            self.wfile.flush()

    do_GET = do_HEAD = do_POST = do_OPTIONS = do_DELETE = do_PUT = do_PATCH = _atender

    def log_message(self, *args):
        pass


class ServidorFalso:
    def __init__(self, responder):
        self._http = ThreadingHTTPServer(("127.0.0.1", 0), _Manejador)
        self._http.daemon_threads = True
        self._http.responder = responder
        self._http.registro = []
        self.puerto = self._http.server_address[1]
        self.url = f"http://127.0.0.1:{self.puerto}"
        self._hilo = threading.Thread(target=self._http.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    def __enter__(self):
        self._hilo.start()
        return self

    def __exit__(self, *exc):
        self._http.shutdown()
        self._http.server_close()
        self._hilo.join(timeout=5)

    @property
    def peticiones(self):
        return list(self._http.registro)

    def rutas(self):
        return [(p.metodo, p.ruta) for p in self.peticiones]


def _respuesta_json(estado, datos, cabeceras):
    return estado, {**cabeceras, "Content-Type": _JSON}, json.dumps(datos, separators=(",", ":")).encode("utf-8")


def desde_rutas(rutas, defecto=(404, {}, b"")):
    """Responde según un dict {"METODO /ruta": (estado, cabeceras, cuerpo)}."""
    return lambda p: rutas.get(f"{p.metodo} {p.ruta}", defecto)


def props_llamacpp(build=BUILD_LLAMACPP, modelo=RUTA_MODELO_FALSA, plantilla="{{ messages }}", **extra):
    """Cuerpo de `/props` con los campos de la captura real."""
    return {
        "default_generation_settings": {"params": {"seed": 4294967295, "temperature": 0.8}, "n_ctx": 256},
        "total_slots": 1, "model_alias": modelo, "model_ftype": "Q4_K - Medium", "model_path": modelo,
        "modalities": {"vision": False, "video": False, "audio": False},
        "media_marker": "<__media_falso__>", "endpoint_slots": True, "endpoint_props": False,
        "endpoint_metrics": False, "ui": True, "ui_settings": {}, "chat_template": plantilla,
        "chat_template_caps": {"supports_tools": True}, "bos_token": "<|endoftext|>",
        "eos_token": "<|im_end|>", "build_info": build, "is_sleeping": False, "cors_proxy_enabled": False,
        **extra,
    }


def _cors_llamacpp(cors, credenciales, origen):
    """`Access-Control-Allow-Origin` según `--cors-origins`; None si no se envía."""
    if cors == "*" and credenciales:
        return origen or ""         # refleja el Origin; vacía si la petición no lo lleva
    if cors == "localhost":
        host = origen.partition("://")[2].rpartition(":")[0] or origen.partition("://")[2]
        return origen if origen and host in ("localhost", "127.0.0.1", "[::1]") else None
    return cors


def llamacpp(clave=None, webui=True, prefijo="", build=BUILD_LLAMACPP, modelo=RUTA_MODELO_FALSA,
             cargando=False, server="llama.cpp", plantilla="{{ messages }}", prompt=None, dormido=False,
             metricas=False, props_post=False, guardado_slots=False, sin_slots=False, adaptadores=(),
             herramientas=(), cors_proxy=False, router=False, cors="*", credenciales=True, validar_host=False):
    """llama-server b11583. Orden real del middleware: OPTIONS, carga, clave, enrutado.
    Las rutas públicas con clave no incluyen el prefijo. `prompt` es el texto que publicaría
    `/slots` con LLAMA_SERVER_SLOTS_DEBUG. Los parámetros de abajo reproducen cada arranque."""
    base = {"Access-Control-Allow-Origin": ""}
    if server:
        base["Server"] = server
    version = build.split("-", 1)[0]
    if router:
        fila = {"id": "alias-router", "aliases": [], "tags": [], "object": "model", "owned_by": "llamacpp", "created": 1,
                "status": {"value": "unloaded", "args": ["/srv/llama-server", "--model", modelo], "preset": f"model = {modelo}"}}
        modelos = {"data": [fila], "object": "list"}
    else:
        modelos = {"models": [{"name": modelo}], "object": "list", "data": [
            {"id": modelo, "aliases": [], "tags": [], "object": "model", "created": 1, "owned_by": "llamacpp", "meta": {}}]}

    def responder(p):
        ruta = p.ruta.partition("?")[0]
        if validar_host and p.cabeceras.get("host", "").partition(":")[0] != "127.0.0.1":
            return 421, base, b""
        acao = _cors_llamacpp(cors, credenciales, p.cabeceras.get("origin", ""))
        cabeceras_cors = {k: v for k, v in base.items() if k != "Access-Control-Allow-Origin"}
        if acao is not None:
            cabeceras_cors["Access-Control-Allow-Origin"] = acao
        if p.metodo == "OPTIONS":
            return 200, {**cabeceras_cors, "Access-Control-Allow-Credentials": "true" if credenciales else "false",
                         "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS", "Access-Control-Allow-Headers": "*"}, b""
        if cargando and ruta in ("/health", "/props"):
            return _respuesta_json(503, {"error": {"message": "Loading model", "type": "unavailable_error", "code": 503}}, base)
        if clave and ruta not in _PUBLICAS_LLAMACPP and p.cabeceras.get("authorization") != f"Bearer {clave}":
            return _respuesta_json(401, _CLAVE_INVALIDA, base)
        if prefijo:
            if not ruta.startswith(prefijo + "/"):
                return _respuesta_json(404, _NO_ENCONTRADO, base)
            ruta = ruta[len(prefijo):]
        if ruta in ("/health", "/v1/health"):
            return _respuesta_json(200, {"status": "ok"}, base)
        if ruta == "/props":
            if router:
                return _respuesta_json(200, {"role": "router", "max_instances": 4, "models_autoload": False, "model_alias": "llama-server",
                                             "model_path": "none", "default_generation_settings": {"params": None, "n_ctx": 0},
                                             "ui_settings": {}, "build_info": build, "cors_proxy_enabled": cors_proxy}, base)
            indicadores = {"is_sleeping": dormido, "endpoint_metrics": metricas, "endpoint_props": props_post,
                           "endpoint_slots": not sin_slots, "ui": webui, "cors_proxy_enabled": cors_proxy}
            return _respuesta_json(200, props_llamacpp(build, modelo, plantilla, **indicadores), base)
        if ruta in ("/v1/models", "/models"):
            return _respuesta_json(200, modelos, base)
        if ruta == "/metrics":
            if metricas:
                return 200, {**base, "Content-Type": "text/plain"}, b"llamacpp:prompt_tokens_total 1\n"
            return _respuesta_json(501, _NO_DISPONIBLE, base)
        if router and ruta in ("/slots", "/lora-adapters"):
            return _respuesta_json(400, {"error": {"code": 400, "message": "model name is missing from the request"}}, base)
        if ruta == "/slots":
            if sin_slots:
                return _respuesta_json(501, _NO_DISPONIBLE, base)
            fila = {"id": 0, "n_ctx": 256, "speculative": False, "is_processing": False, "params": {"lora": list(adaptadores)}}
            if prompt:
                fila.update({"prompt": prompt, "generated": prompt})
            return _respuesta_json(200, [fila], base)
        if p.metodo == "POST" and ruta.startswith("/slots/"):
            if not guardado_slots:
                return _respuesta_json(501, _NO_DISPONIBLE, base)
            return _respuesta_json(400, {"error": {"code": 400, "message": "Invalid action", "type": "invalid_request_error"}}, base)
        if ruta == "/lora-adapters":
            return _respuesta_json(200, [{"id": i, "path": a, "scale": 1.0} for i, a in enumerate(adaptadores)], base)
        if ruta == "/tools":
            if not herramientas:
                return _respuesta_json(403, {"error": {"code": 403, "message": "tools disabled"}}, base)
            return _respuesta_json(200, list(herramientas), base)
        if ruta == "/cors-proxy":
            if cors_proxy:
                return _respuesta_json(500, {"error": {"code": 500, "message": "invalid URL: no scheme"}}, base)
            return _respuesta_json(403, {"error": {"code": 403, "message": "disabled"}}, base)
        if ruta in ("/", "/index.html") and webui:
            if "gzip" not in p.cabeceras.get("accept-encoding", ""):
                return 415, {**base, "Content-Type": "text/plain"}, b"Error: gzip is not supported by this browser"
            cuerpo = gzip.compress(b"<!doctype html><html></html>")
            return 200, {**base, "Content-Encoding": "gzip", "Content-Type": "text/html; charset=utf-8"}, cuerpo
        if ruta == "/build.json" and webui:
            if "gzip" not in p.cabeceras.get("accept-encoding", ""):
                return 415, {**base, "Content-Type": "text/plain"}, b"Error: gzip is not supported by this browser"
            cuerpo = gzip.compress(json.dumps({"version": version}, separators=(",", ":")).encode("utf-8"))
            return 200, {**base, "Content-Encoding": "gzip", "Content-Type": "application/json"}, cuerpo
        return _respuesta_json(404, _NO_ENCONTRADO, base)

    return responder


def vllm(clave=None, version="0.33.0", modelo="org/modelo-falso", docs=True, metricas=True, rust=False,
         server="uvicorn", desarrollo=False, pooling=False, tokens_only=False, perfilador=False, tolerancia=False,
         tokenizador=None, eventos_kv=None, comodin=False, raiz=None, cors=None):
    """vLLM 0.33.0 según su código: `--api-key` solo protege cuatro prefijos y OPTIONS queda exento."""
    base = {"Server": server} if server else {}
    solo_post = set(_SOLO_POST_VLLM)
    solo_post |= _SOLO_POST_POOLING if pooling else set()
    solo_post |= SOLO_POST_DESARROLLO if desarrollo else set()
    solo_post |= {"/abort_requests"} if tokens_only else set()
    solo_post |= {"/start_profile", "/stop_profile"} if perfilador else set()
    solo_post |= {"/fault_tolerance/apply"} if tolerancia else set()

    def responder(p):
        ruta = p.ruta.partition("?")[0]
        if p.metodo == "OPTIONS":
            if cors is None:            # sin orígenes permitidos, la comprobación previa se rechaza
                return 400, base, b"Disallowed CORS origin"
            return 200, {**base, "Access-Control-Allow-Origin": cors}, b""
        if clave and ruta.startswith(_PROTEGIDAS_VLLM) and p.cabeceras.get("authorization") != f"Bearer {clave}":
            return _respuesta_json(401, {"error": "Unauthorized"}, base)
        if ruta in solo_post:
            return _respuesta_json(405, {"detail": "Method Not Allowed"}, {**base, "Allow": "POST"})
        if ruta == "/load":
            return _respuesta_json(200, {"server_load": 3}, base)
        if ruta == "/kv_event_sources":
            return _respuesta_json(200, eventos_kv or {}, base)
        if ruta == "/tokenizer_info" and tokenizador is not None:
            return _respuesta_json(200, {"chat_template": tokenizador}, base)
        if ruta == "/version":
            datos = {"version": version}
            if rust:
                datos["rust_frontend_version"] = "0.1.0"
            return _respuesta_json(200, datos, base)
        if ruta == "/metrics" and metricas:
            texto = (b"# HELP vllm:num_requests_running x\nvllm:num_requests_running{model_name=\"m\"} 0.0\n"
                     b"vllm:num_requests_waiting{model_name=\"m\"} 0.0\n")
            return 200, {**base, "Content-Type": "text/plain"}, texto
        if ruta == "/v1/models":
            fila = {"id": modelo, "object": "model", "created": 1, "owned_by": "vllm", "root": raiz or modelo, "parent": None, "permission": []}
            return _respuesta_json(200, {"object": "list", "data": [fila]}, base)
        if ruta == "/openapi.json" and docs:
            rutas = {"/tokenize": {}, "/detokenize": {}, "/version": {}}
            return _respuesta_json(200, {"openapi": "3.1.0", "info": {"title": "FastAPI", "version": "0.1.0"}, "paths": rutas}, base)
        if ruta == "/health":
            return 200, base, b""
        if comodin:
            return _respuesta_json(200, {"ok": True}, base)
        return _respuesta_json(404, {"detail": "Not Found"}, base)

    return responder


def generico_openai(clave=None, modelo="alias-falso"):
    """Servidor con API de OpenAI y nada más que lo distinga."""
    def responder(p):
        if p.ruta != "/v1/models":
            return _respuesta_json(404, {"error": "no existe"}, {})
        if clave:
            return _respuesta_json(401, {"error": {"message": "falta la clave"}}, {})
        return _respuesta_json(200, {"object": "list", "data": [{"id": modelo, "object": "model"}]}, {})

    return responder


def http_simple(p):
    """Servicio HTTP ajeno a los LLM, como `python -m http.server`."""
    if p.ruta == "/":
        return 200, {"Server": "SimpleHTTP/0.6 Python/3.13.5", "Content-Type": "text/html"}, b"<html></html>"
    return 404, {"Server": "SimpleHTTP/0.6 Python/3.13.5", "Content-Type": "text/html"}, b"no existe"
