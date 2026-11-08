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
_PUBLICAS_LLAMACPP = {"/health", "/v1/health", "/", "/index.html", "/sw.js", "/manifest.webmanifest",
                      "/_app/version.json", "/build.json", "/favicon.ico"}
_PROTEGIDAS_VLLM = ("/v1", "/v2", "/inference", "/cohere")


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


def props_llamacpp(build=BUILD_LLAMACPP, modelo=RUTA_MODELO_FALSA):
    """Cuerpo de `/props` con los campos de la captura real."""
    return {
        "default_generation_settings": {"params": {"seed": 4294967295, "temperature": 0.8}, "n_ctx": 256},
        "total_slots": 1, "model_alias": modelo, "model_ftype": "Q4_K - Medium", "model_path": modelo,
        "modalities": {"vision": False, "video": False, "audio": False},
        "media_marker": "<__media_falso__>", "endpoint_slots": True, "endpoint_props": False,
        "endpoint_metrics": False, "ui": True, "ui_settings": {}, "chat_template": "{{ messages }}",
        "chat_template_caps": {"supports_tools": True}, "bos_token": "<|endoftext|>",
        "eos_token": "<|im_end|>", "build_info": build, "is_sleeping": False, "cors_proxy_enabled": False,
    }


def llamacpp(clave=None, webui=True, prefijo="", build=BUILD_LLAMACPP, modelo=RUTA_MODELO_FALSA,
             cargando=False, server="llama.cpp"):
    """llama-server b11583. Orden real del middleware: OPTIONS, carga, clave, enrutado.
    Las rutas públicas con clave no incluyen el prefijo."""
    base = {"Access-Control-Allow-Origin": ""}
    if server:
        base["Server"] = server
    version = build.split("-", 1)[0]
    modelos = {"models": [{"name": modelo}], "object": "list", "data": [
        {"id": modelo, "aliases": [], "tags": [], "object": "model", "created": 1, "owned_by": "llamacpp", "meta": {}}]}

    def responder(p):
        ruta = p.ruta.partition("?")[0]
        if p.metodo == "OPTIONS":
            return 200, {**base, "Access-Control-Allow-Credentials": "true"}, b""
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
            return _respuesta_json(200, props_llamacpp(build, modelo), base)
        if ruta in ("/v1/models", "/models"):
            return _respuesta_json(200, modelos, base)
        if ruta == "/metrics":
            return _respuesta_json(501, {"error": {"code": 501, "type": "not_supported_error", "message": "x"}}, base)
        if ruta == "/slots":
            return _respuesta_json(200, [{"id": 0, "n_ctx": 256, "speculative": False, "is_processing": False}], base)
        if ruta == "/build.json" and webui:
            if "gzip" not in p.cabeceras.get("accept-encoding", ""):
                return 415, {**base, "Content-Type": "text/plain"}, b"Error: gzip is not supported by this browser"
            cuerpo = gzip.compress(json.dumps({"version": version}, separators=(",", ":")).encode("utf-8"))
            return 200, {**base, "Content-Encoding": "gzip", "Content-Type": "application/json"}, cuerpo
        return _respuesta_json(404, _NO_ENCONTRADO, base)

    return responder


def vllm(clave=None, version="0.33.0", modelo="org/modelo-falso", docs=True, metricas=True, rust=False,
         server="uvicorn"):
    """vLLM 0.33.0 según su código: `--api-key` solo protege cuatro prefijos."""
    base = {"Server": server} if server else {}

    def responder(p):
        ruta = p.ruta.partition("?")[0]
        if clave and ruta.startswith(_PROTEGIDAS_VLLM) and p.cabeceras.get("authorization") != f"Bearer {clave}":
            return _respuesta_json(401, {"error": "Unauthorized"}, base)
        if ruta == "/version":
            datos = {"version": version}
            if rust:
                datos["rust_frontend_version"] = "0.1.0"
            return _respuesta_json(200, datos, base)
        if ruta == "/metrics" and metricas:
            texto = b"# HELP vllm:num_requests_running x\nvllm:num_requests_running{model_name=\"m\"} 0.0\n"
            return 200, {**base, "Content-Type": "text/plain"}, texto
        if ruta == "/v1/models":
            fila = {"id": modelo, "object": "model", "created": 1, "owned_by": "vllm", "root": modelo, "parent": None, "permission": []}
            return _respuesta_json(200, {"object": "list", "data": [fila]}, base)
        if ruta == "/openapi.json" and docs:
            rutas = {"/tokenize": {}, "/detokenize": {}, "/version": {}}
            return _respuesta_json(200, {"openapi": "3.1.0", "info": {"title": "FastAPI", "version": "0.1.0"}, "paths": rutas}, base)
        if ruta == "/health":
            return 200, base, b""
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
