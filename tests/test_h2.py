"""Pruebas de H2: exposición por servidor sobre el contexto de la identificación.

Las funciones de evaluación se prueban con entradas fabricadas; el sondeo de cada perfil, contra
servidores falsos locales que reproducen las capturas reales. Al final, los dos invariantes de
punta a punta con el CLI: solo peticiones permitidas y ningún secreto en el informe.
"""
import json
import sys
import types
from pathlib import Path

import pytest

from mrrobotia import cli, red
from mrrobotia.contexto import Contexto, ServidorDetectado, rotular, texto_direccion
from mrrobotia.modulos import h2_exposicion as h2
from mrrobotia.modulos import h2_identificacion as h2id
from mrrobotia.modulos.h2_exposicion import H2Exposicion
from mrrobotia.modulos.h2_identificacion import H2Identificacion
from mrrobotia.nucleo import Severidad
from mrrobotia.perfiles import GENERICO, PERFILES
from mrrobotia.perfiles.base import es_ruta_absoluta, hallazgo_autenticacion
from mrrobotia.perfiles.llamacpp import RUTA_ACCION_NULA
from mrrobotia.procesos import Proceso
from mrrobotia.red import ClienteHTTP, Respuesta
from servidor_falso import RUTA_MODELO_FALSA, ServidorFalso, desde_rutas, generico_openai, llamacpp, vllm

LLAMA, VLLM = PERFILES
CANARIO_CLAVE = "canario-clave-no-debe-salir"
CANARIO_PROMPT = "canario-prompt-no-debe-salir"
CANARIO_PLANTILLA = "canario-plantilla-no-debe-salir"
RUTA_CANARIO = "/srv/ruta-canario/privada/modelo.gguf"


def objetivo(**extra):
    base = {"nombre": "prueba", "host": "127.0.0.1",
            "autorizacion": {"tengo_autorizacion": True, "autorizado_por": "x", "ambito": "x", "fecha": "2026-01-01"}}
    return {**base, **extra}


def servidor(puerto=1, tipo="llama.cpp", **kw):
    return ServidorDetectado(**{"tipo": tipo, "host": "127.0.0.1", "puerto": puerto, "fuentes": ["http"],
                                "enlace": "loopback", **kw})


def ids(hallazgos):
    return [h.id for h in hallazgos]


def uno(hallazgos, id_):
    encontrados = [h for h in hallazgos if h.id == id_]
    assert len(encontrados) == 1, ids(hallazgos)
    return encontrados[0]


def respuesta(estado=200, **cabeceras):
    return Respuesta(estado, {k.replace("_", "-"): v for k, v in cabeceras.items()}, b"")


@pytest.fixture
def aislado(monkeypatch):
    """Sin IP de red ni consulta del propietario real del proceso."""
    monkeypatch.setattr(h2.red, "ip_rutable", lambda: None)
    monkeypatch.setattr(h2.red, "owner_proceso", lambda pid, timeout=10: None)


def auditar(obj, *servidores, activos=True):
    m = H2Exposicion()
    m.activos_ok = activos
    m.contexto = Contexto("linux", servidores=list(servidores))
    return m.ejecutar(obj)


def sondear(responder, s=None, expuesto=False, proxy=False, perfil=LLAMA, prefijo=""):
    s = s or servidor()
    with ServidorFalso(responder) as falso:
        cliente = ClienteHTTP(falso.url + prefijo, timeout=2, post_permitidos=perfil.post_permitidos)
        hallazgos = perfil.sondear(cliente, s, expuesto, proxy)
    return hallazgos, falso.rutas(), s


# -------------------------------------------------------------- tabla de puertos
def test_bind_desde_tabla_clasifica():
    win_todas = "  TCP    0.0.0.0:8080     0.0.0.0:0     LISTENING   1234"
    win_loop = "  TCP    127.0.0.1:8080   0.0.0.0:0     LISTENING   5678"
    lan = "  TCP    192.168.1.50:8080   0.0.0.0:0   LISTENING   4321"
    otro_puerto = "  TCP    127.0.0.1:9999   0.0.0.0:0   LISTENING   9"
    assert red.bind_desde_tabla(win_todas, 8080) == "todas"
    assert red.bind_desde_tabla(win_loop, 8080) == "loopback"
    assert red.bind_desde_tabla(lan, 8080) == ("otra", "192.168.1.50")
    assert red.bind_desde_tabla(otro_puerto, 8080) is None
    assert red.bind_desde_tabla("", 8080) is None


def test_bind_desde_tabla_ipv6_y_prioridad():
    assert red.bind_desde_tabla("  TCP  [::1]:8080  [::]:0  LISTENING  1", 8080) == "loopback"
    assert red.bind_desde_tabla("tcp6 0 0 ::1:8080 :::* LISTEN 1/x", 8080) == "loopback"
    assert red.bind_desde_tabla("tcp6 0 0 :::8080 :::* LISTEN 1/x", 8080) == "todas"
    tabla = ("  TCP  127.0.0.1:8080  0.0.0.0:0  LISTENING  1\n"
             "  TCP  0.0.0.0:8080    0.0.0.0:0  LISTENING  1")
    assert red.bind_desde_tabla(tabla, 8080) == "todas"


def test_pid_desde_tabla():
    assert red.pid_desde_tabla("  TCP    0.0.0.0:8080     0.0.0.0:0     LISTENING   1234", 8080) == 1234
    ss = 'LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:(("llama-server",pid=4321,fd=3))'
    assert red.pid_desde_tabla(ss, 8080) == 4321
    assert red.pid_desde_tabla("tcp 0 0 127.0.0.1:8080 0.0.0.0:* LISTEN 777/llama", 8080) == 777
    assert red.pid_desde_tabla("no hay tabla aquí", 8080) is None


def test_ip_rutable_no_lanza():
    ip = red.ip_rutable()
    assert ip is None or isinstance(ip, str)


# --------------------------------------------------------------------- enlace
def test_evaluar_bind():
    todas = h2._evaluar_bind("todas", "127.0.0.1", False)
    assert todas.id == "H2-BIND" and todas.severidad == Severidad.ALTA
    assert h2._evaluar_bind("loopback", "127.0.0.1", False).severidad == Severidad.INFO
    assert h2._evaluar_bind(("otra", "10.0.0.5"), "127.0.0.1", False).severidad == Severidad.ALTA
    # En loopback cuando se esperaba otra cosa: discrepancia.
    assert h2._evaluar_bind("loopback", "0.0.0.0", False).severidad == Severidad.MEDIA


def test_evaluar_bind_exposicion_declarada_no_es_discrepancia():
    assert h2._evaluar_bind("todas", "0.0.0.0", True).severidad == Severidad.MEDIA
    assert h2._evaluar_bind(("otra", "10.0.0.5"), "10.0.0.5", False).severidad == Severidad.MEDIA
    assert h2._evaluar_bind(("otra", "10.0.0.5"), "10.0.0.6", False).severidad == Severidad.ALTA


def test_enlace_desconocido_no_se_trata_como_loopback():
    h = h2._evaluar_bind(None, "127.0.0.1", False)
    assert h.id == "H2-BIND-DESCONOCIDO" and h.severidad == Severidad.INFO


# ----------------------------------------------------------------- propietario
def test_evaluar_owner_sin_nombre_de_usuario():
    assert h2._evaluar_owner(None, 7).severidad == Severidad.INFO
    privilegiado = h2._evaluar_owner((True, "NT AUTHORITY\\SYSTEM"), 7)
    assert privilegiado.severidad == Severidad.ALTA and "SYSTEM" not in privilegiado.evidencia
    assert h2._evaluar_owner((False, r"EQUIPO\persona"), 7).severidad == Severidad.INFO
    assert "persona" not in h2._evaluar_owner((False, r"EQUIPO\persona"), 7).evidencia


# ------------------------------------------------------------------------ CORS
def cors(acao=None, cred="true", estado=200):
    extras = {"access_control_allow_credentials": cred}
    if acao is not None:
        extras["access_control_allow_origin"] = acao
    return respuesta(estado, **extras)


def test_cors_reflejo_con_credenciales_depende_de_la_clave():
    assert h2._evaluar_cors(cors(h2.ORIGEN_EXTERNO), cors(h2.ORIGEN_LOCAL), "abierta", False).severidad == Severidad.ALTA
    assert h2._evaluar_cors(cors(h2.ORIGEN_EXTERNO), cors(h2.ORIGEN_LOCAL), "activa", False).severidad == Severidad.MEDIA


def test_cors_reflejo_sin_credenciales():
    assert h2._evaluar_cors(cors(h2.ORIGEN_EXTERNO, "false"), cors(), "activa", False).severidad == Severidad.BAJA


def test_cors_comodin():
    assert h2._evaluar_cors(cors("*", "false"), cors("*"), "abierta", False).severidad == Severidad.ALTA
    assert h2._evaluar_cors(cors("*", "false"), cors("*"), "activa", False).severidad == Severidad.BAJA


def test_cors_autenticacion_sin_determinar_no_se_da_por_buena():
    assert h2._evaluar_cors(cors("*", "false"), cors("*"), "indeterminada", False).severidad == Severidad.MEDIA


def test_cors_con_proxy_no_es_alta():
    assert h2._evaluar_cors(cors("*", "false"), cors("*"), "abierta", True).severidad == Severidad.BAJA


def test_cors_solo_origenes_locales():
    h = h2._evaluar_cors(cors(None), cors(h2.ORIGEN_LOCAL), "abierta", False)
    assert h.severidad == Severidad.INFO and "locales" in h.titulo


def test_cors_lista_literal():
    h = h2._evaluar_cors(cors("https://a.test,https://b.test"), cors(), "activa", False)
    assert h.severidad == Severidad.BAJA and "lista" in h.titulo


def test_cors_origen_fijo_saneado():
    h = h2._evaluar_cors(cors("https://app.test"), cors(), "abierta", False)
    assert h.severidad == Severidad.INFO and "app.test" in h.evidencia


@pytest.mark.parametrize("estado", [None, 404, 405])
def test_cors_no_concluyente_no_se_presenta_como_seguro(estado):
    h = h2._evaluar_cors(respuesta(estado), cors(), "abierta", False)
    assert h.severidad == Severidad.INFO and "CORS no admite" not in h.titulo


# ------------------------------------------------------------------------ Host
def test_host_sin_validar_y_sin_clave_es_dns_rebinding():
    h = h2._evaluar_host(respuesta(200), respuesta(200), "abierta", False)
    assert h.id == "H2-HOST" and h.severidad == Severidad.MEDIA and "rebinding" in h.titulo.lower()


def test_host_sin_validar_con_clave_o_proxy():
    assert h2._evaluar_host(respuesta(401), respuesta(401), "activa", False).severidad == Severidad.INFO
    assert h2._evaluar_host(respuesta(200), respuesta(200), "abierta", True).severidad == Severidad.INFO


def test_host_sin_validar_y_autenticacion_indeterminada():
    h = h2._evaluar_host(respuesta(404), respuesta(404), "indeterminada", False)
    assert (h.severidad, h.estado) == (Severidad.BAJA, "potencial")


def test_host_rechazado():
    assert "rechaza" in h2._evaluar_host(respuesta(200), respuesta(421), "abierta", False).titulo


def test_host_no_concluyente():
    assert "sin concluir" in h2._evaluar_host(respuesta(200), respuesta(500), "abierta", False).titulo
    assert h2._evaluar_host(respuesta(None), respuesta(200), "abierta", False).severidad == Severidad.INFO


# ------------------------------------------------------------------- TLS y compuesta
def test_evaluar_tls():
    assert h2._evaluar_tls("https", True).severidad == Severidad.INFO
    assert h2._evaluar_tls("http", True).severidad == Severidad.ALTA
    assert h2._evaluar_tls("http", False).severidad == Severidad.BAJA


def test_severidad_compuesta():
    critico = h2._severidad_compuesta("todas", "abierta", False, True)
    assert critico.id == "H2-EXPOSICION" and critico.severidad == Severidad.CRITICA
    assert h2._severidad_compuesta("todas", "activa", False, True).severidad == Severidad.ALTA
    assert h2._severidad_compuesta("todas", "abierta", True, True).severidad == Severidad.ALTA
    assert h2._severidad_compuesta("loopback", "abierta", False, False).severidad == Severidad.BAJA
    assert h2._severidad_compuesta("loopback", "activa", False, False).severidad == Severidad.INFO


def test_severidad_compuesta_no_da_por_buena_la_duda():
    expuesto = h2._severidad_compuesta("todas", "indeterminada", False, True)
    assert expuesto.severidad == Severidad.ALTA and "sin determinar" in expuesto.evidencia
    assert "exige API key" not in h2._severidad_compuesta("loopback", "indeterminada", False, False).evidencia


def test_severidad_compuesta_enlace_desconocido():
    h = h2._severidad_compuesta(None, "abierta", False, False)
    assert h.severidad == Severidad.MEDIA and "desconocido" in h.titulo
    assert h2._severidad_compuesta(None, "activa", False, False).severidad == Severidad.INFO
    # Lo observado manda: si desde la red responde, está expuesto aunque no se conozca el enlace.
    assert h2._severidad_compuesta(None, "abierta", False, True).severidad == Severidad.CRITICA


# ----------------------------------------------------- llama.cpp: sondear
def test_sondear_por_defecto():
    h, rutas, s = sondear(llamacpp())
    assert uno(h, "H2-AUTH").severidad == Severidad.MEDIA and s.autenticacion == "abierta"
    props = uno(h, "H2-PROPS")
    assert props.severidad == Severidad.MEDIA and "modelo-falso-q4.gguf" in props.evidencia
    assert RUTA_MODELO_FALSA not in props.evidencia
    assert uno(h, "H2-BUILD").evidencia == "build = b11583-988015788" and s.version == "b11583-988015788"
    assert uno(h, "H2-MODELS").severidad == Severidad.MEDIA
    assert uno(h, "H2-WEBUI").severidad == Severidad.BAJA
    assert "sin clave, ofrece una consola" in uno(h, "H2-WEBUI").recomendacion
    assert "H2-METRICS" not in ids(h) and "H2-SLOT-SAVE" not in ids(h)


def test_sondear_no_pide_metrics_ni_con_ellas_activas():
    h, rutas, _ = sondear(llamacpp(metricas=True))
    assert uno(h, "H2-METRICS").severidad == Severidad.BAJA and "/props indica" in uno(h, "H2-METRICS").evidencia
    assert ("GET", "/metrics") not in rutas


def test_sondear_metricas_expuestas():
    assert uno(sondear(llamacpp(metricas=True), expuesto=True)[0], "H2-METRICS").severidad == Severidad.MEDIA


def test_slots_sin_texto_se_gradua_baja():
    h, _, _ = sondear(llamacpp())
    slots = uno(h, "H2-SLOTS")
    assert slots.severidad == Severidad.BAJA and "1 slot" in slots.evidencia and "sin texto" in slots.titulo
    assert "--no-slots" in slots.recomendacion
    assert uno(sondear(llamacpp(), expuesto=True)[0], "H2-SLOTS").severidad == Severidad.MEDIA


def test_slots_con_texto_se_gradua_alta_y_no_lo_vuelca():
    h, _, _ = sondear(llamacpp(prompt=CANARIO_PROMPT))
    slots = uno(h, "H2-SLOTS")
    assert slots.severidad == Severidad.ALTA and "texto" in slots.titulo and "LLAMA_SERVER_SLOTS_DEBUG" in slots.recomendacion
    assert CANARIO_PROMPT not in repr(h)
    assert uno(sondear(llamacpp(prompt=CANARIO_PROMPT), expuesto=True)[0], "H2-SLOTS").severidad == Severidad.CRITICA


def test_slots_senala_el_uso_de_adaptadores():
    h, _, _ = sondear(llamacpp(adaptadores=("/a/l.gguf",)))
    assert "adaptador" in uno(h, "H2-SLOTS").evidencia


def test_sondear_con_no_slots():
    h, rutas, _ = sondear(llamacpp(sin_slots=True))
    assert "H2-SLOTS" not in ids(h) and ("GET", "/slots") not in rutas


def test_slots_sin_respuesta_no_se_presenta_como_seguro():
    def responder(p):
        if p.ruta == "/slots":
            raise ConnectionAbortedError("sin respuesta")
        return llamacpp()(p)

    h, _, _ = sondear(responder)
    assert uno(h, "H2-SLOTS").severidad == Severidad.INFO


def test_dormido_no_despierta_al_servidor():
    h, rutas, _ = sondear(llamacpp(dormido=True))
    assert not {("GET", "/slots"), ("GET", "/lora-adapters"), ("POST", RUTA_ACCION_NULA)} & set(rutas)
    slots = uno(h, "H2-SLOTS")
    assert slots.estado == "potencial" and "no despertarlo" in slots.evidencia


def test_guardado_de_slots_detectado_con_post_inocua():
    h, rutas, _ = sondear(llamacpp(guardado_slots=True))
    assert uno(h, "H2-SLOT-SAVE").severidad == Severidad.ALTA and ("POST", RUTA_ACCION_NULA) in rutas
    assert "H2-SLOT-SAVE" not in ids(sondear(llamacpp())[0])


def test_cors_proxy_por_indicador():
    h, rutas, _ = sondear(llamacpp(cors_proxy=True))
    assert uno(h, "H2-CORS-PROXY").severidad == Severidad.CRITICA and ("GET", "/cors-proxy") not in rutas


def test_cors_proxy_sin_indicador_prueba_la_ruta_sin_url():
    datos = {"build_info": "b9000-abc", "default_generation_settings": {}}
    rutas_falsas = {"GET /props": (200, {"Server": "llama.cpp"}, json.dumps(datos).encode()),
                    "GET /cors-proxy": (500, {"Server": "llama.cpp"}, b'{"error":{"message":"invalid URL: no scheme"}}')}
    h, rutas, _ = sondear(desde_rutas(rutas_falsas))
    assert uno(h, "H2-CORS-PROXY") and ("GET", "/cors-proxy") in rutas


@pytest.mark.parametrize("herramientas,severidad", [
    ([{"tool": "get_info", "permissions": {"write": False}}], Severidad.ALTA),
    ([{"tool": "read_file", "permissions": {"write": False}}, {"tool": "write_file", "permissions": {"write": True}}], Severidad.CRITICA),
    ([{"tool": "exec_shell_command", "permissions": {"write": False}}], Severidad.CRITICA),
])
def test_herramientas(herramientas, severidad):
    h, rutas, _ = sondear(llamacpp(herramientas=herramientas))
    assert uno(h, "H2-TOOLS").severidad == severidad and herramientas[0]["tool"] in uno(h, "H2-TOOLS").evidencia
    assert ("POST", "/tools") not in rutas


def test_adaptadores_lora():
    h, _, _ = sondear(llamacpp(adaptadores=("/srv/privado/l.gguf",)))
    lora = uno(h, "H2-LORA")
    assert lora.severidad == Severidad.MEDIA and "1 adaptador" in lora.evidencia and "/srv/privado" not in lora.evidencia
    assert "H2-LORA" not in ids(sondear(llamacpp())[0])         # lista vacía


def test_props_escritura():
    assert uno(sondear(llamacpp(props_post=True))[0], "H2-PROPS-ESCRITURA").severidad == Severidad.BAJA


def test_sondear_con_clave():
    h, rutas, s = sondear(llamacpp(clave="k"))
    assert uno(h, "H2-AUTH").severidad == Severidad.INFO and s.autenticacion == "activa"
    build = uno(h, "H2-BUILD")
    assert build.evidencia == "build = b11583; /build.json la publica sin clave" and s.version == "b11583"
    assert not {"H2-PROPS", "H2-SLOTS", "H2-MODELS", "H2-METRICS"} & set(ids(h))
    assert ("GET", "/slots") not in rutas and ("POST", RUTA_ACCION_NULA) not in rutas
    webui = uno(h, "H2-WEBUI")
    assert "consola" not in webui.recomendacion and "también sin clave" in webui.recomendacion


def test_sondear_con_clave_y_sin_webui():
    h, _, s = sondear(llamacpp(clave="k", webui=False))
    assert uno(h, "H2-BUILD").evidencia == "build = desconocida" and "H2-WEBUI" not in ids(h) and s.version is None


def test_version_del_contexto_se_conserva_si_no_hay_otra():
    h, _, s = sondear(llamacpp(clave="k", webui=False), servidor(version="b100-abc"))
    assert uno(h, "H2-BUILD").evidencia == "build = b100-abc" and s.version == "b100-abc"


def test_modelos_publicos_con_clave_en_builds_antiguas():
    def responder(p):
        if p.ruta == "/v1/models":
            return llamacpp()(p)
        return llamacpp(clave="k", build="b9000-abc")(p)

    h, _, s = sondear(responder)
    assert s.version == "b9000" and "b10518" in uno(h, "H2-MODELS").evidencia


def test_webui_exige_gzip():
    """Sin `Accept-Encoding: gzip`, llama-server responde 415 y la interfaz pasaría inadvertida."""
    _, rutas, _ = sondear(llamacpp())
    assert ("GET", "/") in rutas


def test_sondear_sin_webui():
    h, rutas, _ = sondear(llamacpp(webui=False))
    assert "H2-WEBUI" not in ids(h) and ("GET", "/") not in rutas


def test_prefijo_conocido():
    h, rutas, _ = sondear(llamacpp(prefijo="/lab"), prefijo="/lab")
    assert uno(h, "H2-AUTH").severidad == Severidad.MEDIA and ("GET", "/lab/props") in rutas and uno(h, "H2-WEBUI")


def test_prefijo_desconocido_es_indeterminado():
    h, _, s = sondear(llamacpp(prefijo="/lab"))
    aut = uno(h, "H2-AUTH")
    assert aut.severidad == Severidad.INFO and "prefijo" in aut.evidencia and "No se pudo" in aut.titulo
    assert s.autenticacion is None and "H2-PROPS" not in ids(h)


def test_cargando_es_indeterminado():
    h, _, s = sondear(llamacpp(cargando=True), servidor(autenticacion="activa"))
    aut = uno(h, "H2-AUTH")
    assert aut.severidad == Severidad.INFO and "cargando" in aut.evidencia and "el arranque configura una clave" in aut.evidencia
    assert s.autenticacion == "activa"                      # lo no concluyente no lo borra


def test_router_sin_clave():
    h, rutas, _ = sondear(llamacpp(router=True))
    assert uno(h, "H2-ROUTER").severidad == Severidad.MEDIA and "max_instances=4" in uno(h, "H2-ROUTER").evidencia
    assert uno(h, "H2-PROPS").titulo == "El endpoint /props está accesible"     # model_path = "none"
    modelos = uno(h, "H2-MODELS")
    assert modelos.severidad == Severidad.MEDIA and "status.args" in modelos.evidencia and RUTA_MODELO_FALSA not in modelos.evidencia
    assert not {("GET", "/slots"), ("GET", "/lora-adapters"), ("POST", RUTA_ACCION_NULA)} & set(rutas)


def test_router_expuesto():
    h, _, _ = sondear(llamacpp(router=True), expuesto=True)
    assert uno(h, "H2-ROUTER").severidad == Severidad.ALTA and uno(h, "H2-MODELS").severidad == Severidad.ALTA


def test_identificador_de_hugging_face_no_es_ruta():
    def responder(p):
        if p.ruta == "/v1/models":
            return 200, {"Server": "llama.cpp"}, b'{"object":"list","data":[{"id":"org/modelo:Q4_K_M"}]}'
        return llamacpp()(p)

    assert uno(sondear(responder)[0], "H2-MODELS").severidad == Severidad.BAJA


def test_post_fuera_de_la_lista_blanca_no_se_puede():
    with pytest.raises(ValueError):
        ClienteHTTP("http://127.0.0.1:1", post_permitidos=LLAMA.post_permitidos).post_inocuo("/lora-adapters")


# ------------------------------------------------------------ genérico
def test_generico_abierto():
    h, rutas, s = sondear(generico_openai(), servidor(tipo="generico"), perfil=GENERICO)
    assert uno(h, "H2-AUTH").severidad == Severidad.MEDIA and uno(h, "H2-MODELS").severidad == Severidad.BAJA
    assert s.autenticacion == "abierta" and rutas == [("GET", "/v1/models")]


def test_generico_con_clave():
    h, _, s = sondear(generico_openai(clave="k"), servidor(tipo="generico"), perfil=GENERICO)
    assert uno(h, "H2-AUTH").severidad == Severidad.INFO and s.autenticacion == "activa" and "H2-MODELS" not in ids(h)


def test_generico_expuesto_sin_clave_es_critico():
    assert uno(sondear(generico_openai(), servidor(tipo="generico"), expuesto=True, perfil=GENERICO)[0],
               "H2-AUTH").severidad == Severidad.CRITICA


def test_generico_sin_api_es_indeterminado():
    h, _, s = sondear(desde_rutas({}), servidor(tipo="otro:algo", autenticacion="abierta"), perfil=GENERICO)
    assert "No se pudo" in uno(h, "H2-AUTH").titulo and s.autenticacion == "abierta"


# ----------------------------------------------------------------- módulo: sin datos
def test_sin_contexto_un_info_y_nada_mas():
    m = H2Exposicion()
    m.activos_ok = True
    h = m.ejecutar(objetivo())
    assert ids(h) == ["H2-SIN-CONTEXTO"] and h[0].severidad == Severidad.INFO


def test_sin_servidores(aislado):
    h = auditar(objetivo())
    assert ids(h) == ["H2-SIN-SERVIDOR"]


def test_sin_consentimiento_solo_lo_pasivo(aislado, monkeypatch):
    monkeypatch.setattr(h2.red, "ClienteHTTP", lambda *a, **k: pytest.fail("no debe crear cliente"))
    monkeypatch.setattr(h2.red, "sondear", lambda *a, **k: pytest.fail("no debe conectar"))
    h = auditar(objetivo(), servidor(enlace="todas"), servidor(2, pid=5), activos=False)
    assert ids(h).count("H2-ACTIVO-OMITIDO") == 1
    assert ids(h).count("H2-BIND") == 2 and ids(h).count("H2-OWNER") == 2
    assert "requiere --permitir-activos" in uno(h, "H2-ACTIVO-OMITIDO").evidencia
    assert not {"H2-PORT", "H2-AUTH", "H2-EXPOSICION"} & set(ids(h))


def test_host_no_local_exige_confirmacion(aislado, monkeypatch):
    monkeypatch.setattr(h2.red, "sondear", lambda *a, **k: pytest.fail("no debe conectar"))
    h = auditar(objetivo(host="203.0.113.9", endpoint="http://203.0.113.9:8080/v1"), servidor(8080, host="203.0.113.9", enlace=None))
    assert "confirmo_no_local" in uno(h, "H2-ACTIVO-OMITIDO").evidencia and "H2-BIND-DESCONOCIDO" in ids(h)


def test_regla_de_consentimiento_compartida():
    m = H2Identificacion()
    assert m.motivo_omision_activa({"autorizacion": {}}, False) == "host no local sin confirmo_no_local"
    assert "permitir_activos" in m.motivo_omision_activa({"autorizacion": {}}, True)
    m.activos_ok = True
    assert m.motivo_omision_activa({"autorizacion": {"confirmo_no_local": True}}, False) is None
    assert m.motivo_omision_activa({"autorizacion": {}}, True) is None


def test_puerto_cerrado_no_recibe_http(aislado, monkeypatch):
    monkeypatch.setattr(h2.red, "sondear", lambda *a, **k: False)
    monkeypatch.setattr(h2.red, "ClienteHTTP", lambda *a, **k: pytest.fail("no debe crear cliente"))
    h = auditar(objetivo(), servidor(18099))
    assert "cerrado" in uno(h, "H2-PORT").titulo and "H2-AUTH" not in ids(h)


def test_solo_declarado_no_recibe_http(aislado, monkeypatch):
    with ServidorFalso(llamacpp()) as s:
        h = auditar(objetivo(), servidor(s.puerto, fuentes=["declarado"], confianza="baja"))
    assert uno(h, "H2-SIN-CONFIRMAR") and s.peticiones == [] and "H2-AUTH" not in ids(h)


def test_forzado_si_recibe_http(aislado):
    with ServidorFalso(llamacpp()) as s:
        h = auditar(objetivo(), servidor(s.puerto, fuentes=["forzado"]))
    assert uno(h, "H2-AUTH") and s.peticiones


def test_sin_puerto_solo_lo_pasivo(aislado, monkeypatch):
    monkeypatch.setattr(h2.red, "sondear", lambda *a, **k: pytest.fail("no debe conectar"))
    h = auditar(objetivo(), servidor(None, enlace=None, senales=["socket UNIX: sin puerto TCP"]))
    assert uno(h, "H2-SIN-PUERTO") and "H2-OWNER" in ids(h) and "H2-BIND-DESCONOCIDO" in ids(h)
    assert "H2-PORT" not in ids(h)


def test_un_fallo_del_perfil_no_llega_al_llamador(aislado, monkeypatch):
    def falla(*a):
        raise RuntimeError("fallo de perfil")

    monkeypatch.setattr(LLAMA, "sondear", falla)
    with ServidorFalso(llamacpp()) as s:
        h = auditar(objetivo(), servidor(s.puerto))
    assert uno(h, "H2-ERROR").severidad == Severidad.INFO and "RuntimeError" in uno(h, "H2-ERROR").evidencia
    assert "H2-BIND" in ids(h)


# ------------------------------------------------------------ módulo: auditoría
def test_auditoria_completa_por_defecto(aislado):
    with ServidorFalso(llamacpp()) as s:
        h = auditar(objetivo(endpoint=f"{s.url}/v1/chat/completions"), servidor(s.puerto, autenticacion="abierta"))
    presentes = set(ids(h))
    assert {"H2-BIND", "H2-OWNER", "H2-PORT", "H2-AUTH", "H2-PROPS", "H2-BUILD", "H2-SLOTS", "H2-MODELS", "H2-CORS",
            "H2-HOST", "H2-TLS", "H2-WEBUI", "H2-EXPOSICION"} <= presentes
    assert "H2-LAN" not in presentes
    assert uno(h, "H2-CORS").severidad == Severidad.ALTA        # refleja el Origin y no hay clave
    assert uno(h, "H2-HOST").severidad == Severidad.MEDIA
    assert uno(h, "H2-EXPOSICION").severidad == Severidad.BAJA
    assert uno(h, "H2-TLS").severidad == Severidad.BAJA


def test_cors_con_clave_es_medio_y_host_informativo(aislado):
    with ServidorFalso(llamacpp(clave="k")) as s:
        h = auditar(objetivo(endpoint=s.url), servidor(s.puerto))
    assert uno(h, "H2-CORS").severidad == Severidad.MEDIA and uno(h, "H2-HOST").severidad == Severidad.INFO
    assert uno(h, "H2-EXPOSICION").severidad == Severidad.INFO


@pytest.mark.parametrize("arranque,titulo", [
    ({"cors": "localhost"}, "solo admite orígenes locales"),
    ({"cors": "*", "credenciales": False}, "cualquier web"),
    ({"cors": "http://a.test,http://b.test", "credenciales": False}, "lista"),
])
def test_modos_de_cors_reales(aislado, arranque, titulo):
    with ServidorFalso(llamacpp(**arranque)) as s:
        h = auditar(objetivo(endpoint=s.url), servidor(s.puerto))
    assert titulo in uno(h, "H2-CORS").titulo


def test_host_validado_de_verdad(aislado):
    with ServidorFalso(llamacpp(validar_host=True)) as s:
        h = auditar(objetivo(endpoint=s.url), servidor(s.puerto))
    assert "rechaza" in uno(h, "H2-HOST").titulo


def test_cada_servidor_con_su_rotulo_y_el_declarado_primero(aislado):
    with ServidorFalso(llamacpp()) as a, ServidorFalso(llamacpp(clave="k")) as b:
        h = auditar(objetivo(endpoint=b.url), servidor(b.puerto), servidor(a.puerto))
    evidencias = [x.evidencia for x in h if x.id == "H2-BIND"]
    assert len(evidencias) == 2 and f"127.0.0.1:{b.puerto}" in evidencias[0] and f"127.0.0.1:{a.puerto}" in evidencias[1]
    assert all(x.evidencia.startswith("llama.cpp en 127.0.0.1:") for x in h)


def test_tipo_sin_perfil_usa_el_generico(aislado):
    with ServidorFalso(generico_openai()) as s:
        h = auditar(objetivo(endpoint=s.url), servidor(s.puerto, tipo="otro:ollama"))
    assert uno(h, "H2-AUTH").severidad == Severidad.MEDIA


def test_expuesto_en_lan_sube_la_severidad(aislado, monkeypatch):
    with ServidorFalso(llamacpp()) as s:
        monkeypatch.setattr(h2.red, "ip_rutable", lambda: "127.0.0.1")     # clasificada como loopback: no cuenta
        assert "H2-LAN" not in ids(auditar(objetivo(endpoint=s.url), servidor(s.puerto)))
        reales = red.sondear
        monkeypatch.setattr(h2.red, "ip_rutable", lambda: "192.0.2.10")
        monkeypatch.setattr(h2.red, "sondear", lambda host, puerto, timeout=2: host == "192.0.2.10" or reales(host, puerto, timeout))
        h = auditar(objetivo(endpoint=s.url), servidor(s.puerto))
    assert uno(h, "H2-LAN").severidad == Severidad.ALTA
    assert uno(h, "H2-EXPOSICION").severidad == Severidad.CRITICA and uno(h, "H2-AUTH").severidad == Severidad.CRITICA


def test_host_remoto_alcanzado_cuenta_como_expuesto(monkeypatch):
    monkeypatch.setattr(h2.red, "ip_rutable", lambda: pytest.fail("la IP propia no pinta nada"))
    hallazgos = []
    assert H2Exposicion._expuesto_en_red(servidor(9, host="203.0.113.9", enlace=None), hallazgos) is True
    assert uno(hallazgos, "H2-LAN")


def test_enlace_por_tabla_expuesto(aislado):
    with ServidorFalso(llamacpp()) as s:
        h = auditar(objetivo(endpoint=s.url), servidor(s.puerto, enlace="todas"))
    assert uno(h, "H2-BIND").severidad == Severidad.ALTA and uno(h, "H2-EXPOSICION").severidad == Severidad.CRITICA


def test_sin_respuesta_http_no_afirma_el_esquema(aislado):
    with ServidorFalso(lambda p: (_ for _ in ()).throw(ConnectionAbortedError())) as s:
        h = auditar(objetivo(endpoint=s.url), servidor(s.puerto))
    assert "H2-TLS" not in ids(h) and uno(h, "H2-CORS").severidad == Severidad.INFO


# --------------------------------------------- lo declarado solo vale para su servidor
def test_proxy_y_clave_esperada_solo_para_el_declarado(aislado):
    cfg = {"proxy_autenticador": True, "api_key_esperada": True}
    with ServidorFalso(llamacpp()) as declarado, ServidorFalso(llamacpp()) as otro:
        h = auditar(objetivo(endpoint=declarado.url, exposicion=cfg),
                    servidor(declarado.puerto, enlace="todas"), servidor(otro.puerto, enlace="todas"))
    aut = [x for x in h if x.id == "H2-AUTH"]
    assert aut[0].severidad == Severidad.ALTA and "api_key_esperada" in aut[0].evidencia    # tras proxy, MEDIA + 1
    assert aut[1].severidad == Severidad.CRITICA and "api_key_esperada" not in aut[1].evidencia
    expo = [x.severidad for x in h if x.id == "H2-EXPOSICION"]
    assert expo == [Severidad.ALTA, Severidad.CRITICA]


def test_clave_esperada_sube_la_severidad_en_loopback(aislado):
    with ServidorFalso(llamacpp()) as s:
        h = auditar(objetivo(endpoint=s.url, exposicion={"api_key_esperada": True}), servidor(s.puerto))
    assert uno(h, "H2-AUTH").severidad == Severidad.ALTA


def test_clave_esperada_no_cambia_nada_si_la_tiene(aislado):
    with ServidorFalso(llamacpp(clave="k")) as s:
        h = auditar(objetivo(endpoint=s.url, exposicion={"api_key_esperada": True}), servidor(s.puerto))
    assert uno(h, "H2-AUTH").severidad == Severidad.INFO


def test_sin_puerto_declarado_vale_para_el_unico_servidor(aislado):
    with ServidorFalso(llamacpp()) as s:
        h = auditar(objetivo(exposicion={"api_key_esperada": True}), servidor(s.puerto))
    assert uno(h, "H2-AUTH").severidad == Severidad.ALTA


def test_bind_esperado_del_objetivo(aislado, monkeypatch):
    monkeypatch.setattr(h2.red, "sondear", lambda *a, **k: False)
    h = auditar(objetivo(exposicion={"puerto": 8080, "bind_esperado": "0.0.0.0"}), servidor(8080))
    assert uno(h, "H2-BIND").severidad == Severidad.MEDIA


def test_otro_servidor_se_compara_con_loopback(aislado, monkeypatch):
    monkeypatch.setattr(h2.red, "sondear", lambda *a, **k: False)
    h = auditar(objetivo(exposicion={"puerto": 8080, "bind_esperado": "0.0.0.0"}), servidor(8080, enlace="todas"), servidor(9, enlace="todas"))
    assert [x.severidad for x in h if x.id == "H2-BIND"] == [Severidad.MEDIA, Severidad.ALTA]


# ------------------------------------------------- invariantes de punta a punta
@pytest.fixture
def entorno(monkeypatch):
    """Máquina simulada para ejecutar el CLI entero."""
    e = types.SimpleNamespace(procesos=[], abiertos=set())
    monkeypatch.setattr(h2id.procesos, "enumerar", lambda: list(e.procesos))
    monkeypatch.setattr(h2id.red, "tabla_puertos", lambda: "")
    monkeypatch.setattr(h2id.red, "sondear", lambda host, puerto, timeout=2: puerto in e.abiertos)
    monkeypatch.setattr(h2id.red, "ip_rutable", lambda: None)
    monkeypatch.setattr(h2id.red, "owner_proceso", lambda pid, timeout=10: None)
    return e


def _ejecutar_cli(monkeypatch, tmp_path, obj, *extra):
    ruta = tmp_path / "objetivo.json"
    ruta.write_text(json.dumps(obj), encoding="utf-8")
    salida = tmp_path / "informe"
    monkeypatch.setattr(sys, "argv", ["mrrobotia", "--objetivo", str(ruta), "--salida", str(salida), *extra])
    cli.main()
    return Path(str(salida) + ".json").read_text(encoding="utf-8") + Path(str(salida) + ".md").read_text(encoding="utf-8")


ACTIVO = ("--escaneo", "exposicion,arranque,cve", "--permitir-activos")
_NUNCA = {"/metrics", "/models/sse", "/models/load", "/models/unload", "/completion", "/completions", "/v1/completions",
          "/chat/completions", "/v1/chat/completions", "/v1/responses", "/v1/messages", "/infill", "/tokenize", "/detokenize",
          "/embedding", "/embeddings", "/v1/embeddings", "/rerank", "/v1/rerank"}


def _auditar_cli(entorno, monkeypatch, tmp_path, responder):
    with ServidorFalso(responder) as s:
        entorno.abiertos = {s.puerto}
        _ejecutar_cli(monkeypatch, tmp_path, objetivo(endpoint=s.url, permitir_activos=True), *ACTIVO)
    assert s.peticiones, "debe haber preguntado"
    for p in s.peticiones:
        assert p.metodo in {"GET", "HEAD", "OPTIONS"} or (p.metodo, p.ruta) == ("POST", RUTA_ACCION_NULA), (p.metodo, p.ruta)
        assert p.cuerpo == b"", (p.metodo, p.ruta)
        assert "url=" not in p.ruta and "reload" not in p.ruta
    return {p.ruta.partition("?")[0] for p in s.peticiones}


@pytest.mark.parametrize("responder", [
    llamacpp(), llamacpp(clave="k"), llamacpp(clave="k", webui=False), llamacpp(prompt="p", metricas=True, adaptadores=("/a/l.gguf",)),
    llamacpp(metricas=True), llamacpp(dormido=True), llamacpp(router=True), llamacpp(guardado_slots=True),
    llamacpp(cors_proxy=True, herramientas=[{"tool": "get_info"}]),
], ids=["defecto", "clave", "clave-sin-web", "completo", "metricas", "dormido", "router", "guardado", "herramientas"])
def test_invariante_peticiones_permitidas_en_llamacpp(entorno, monkeypatch, tmp_path, responder):
    assert not _auditar_cli(entorno, monkeypatch, tmp_path, responder) & _NUNCA


@pytest.mark.parametrize("responder", [vllm(), generico_openai()], ids=["vllm", "generico"])
def test_invariante_peticiones_permitidas_en_otros(entorno, monkeypatch, tmp_path, responder):
    # vLLM se reconoce por sus métricas, que allí no tienen efectos.
    assert not _auditar_cli(entorno, monkeypatch, tmp_path, responder) & (_NUNCA - {"/metrics"})


def test_invariante_servidor_dormido_de_punta_a_punta(entorno, monkeypatch, tmp_path):
    with ServidorFalso(llamacpp(dormido=True)) as s:
        entorno.abiertos = {s.puerto}
        _ejecutar_cli(monkeypatch, tmp_path, objetivo(endpoint=s.url, permitir_activos=True), *ACTIVO)
    rutas = {p.ruta.partition("?")[0] for p in s.peticiones}
    assert not rutas & {"/slots", "/lora-adapters", "/slots/0"}


def test_invariante_canarios_servidor_abierto(entorno, monkeypatch, tmp_path):
    arranque = llamacpp(modelo=RUTA_CANARIO, plantilla=CANARIO_PLANTILLA, prompt=CANARIO_PROMPT, adaptadores=(RUTA_CANARIO,))
    with ServidorFalso(arranque) as s:
        entorno.abiertos = {s.puerto}
        informe = _ejecutar_cli(monkeypatch, tmp_path, objetivo(endpoint=s.url, permitir_activos=True), *ACTIVO)
    assert "modelo.gguf" in informe                             # el nombre del fichero sí
    for canario in (CANARIO_PROMPT, CANARIO_PLANTILLA, "ruta-canario"):
        assert canario not in informe


def test_invariante_canarios_router(entorno, monkeypatch, tmp_path):
    with ServidorFalso(llamacpp(modelo=RUTA_CANARIO, router=True)) as s:
        entorno.abiertos = {s.puerto}
        informe = _ejecutar_cli(monkeypatch, tmp_path, objetivo(endpoint=s.url, permitir_activos=True), *ACTIVO)
    assert "ruta-canario" not in informe


def test_invariante_canario_clave_en_la_linea_de_ordenes(entorno, monkeypatch, tmp_path):
    with ServidorFalso(llamacpp(clave=CANARIO_CLAVE, modelo=RUTA_CANARIO)) as s:
        entorno.procesos = [Proceso(100, "llama-server", [
            "/srv/ruta-canario/llama-server", "-m", RUTA_CANARIO, "--port", str(s.puerto), "--api-key", CANARIO_CLAVE,
            "--hf-token", CANARIO_CLAVE, "--mcp-servers-json", CANARIO_CLAVE, "-mu", f"https://u:{CANARIO_CLAVE}@h/m"])]
        entorno.abiertos = {s.puerto}
        informe = _ejecutar_cli(monkeypatch, tmp_path, objetivo(endpoint=s.url, permitir_activos=True), *ACTIVO)
    assert "H2-ARRANQUE-CLAVE-EN-ORDEN" in informe
    assert CANARIO_CLAVE not in informe and "ruta-canario" not in informe


def test_cli_registra_los_modulos():
    etiquetas = {m.etiqueta_escaneo for m in cli.MODULOS}
    assert {"arranque", "cve", "exposicion"} <= etiquetas
    assert cli._resolver_escaneo("arranque,cve") == ({"arranque", "cve"}, False)


# ------------------------------------------------------------ piezas compartidas
@pytest.mark.parametrize("autenticacion,expuesto,proxy,severidad", [
    ("abierta", True, False, Severidad.CRITICA), ("abierta", False, False, Severidad.MEDIA),
    ("abierta", True, True, Severidad.MEDIA), ("activa", True, False, Severidad.INFO),
    ("indeterminada", True, False, Severidad.INFO), (None, False, False, Severidad.INFO),
])
def test_severidad_de_la_autenticacion(autenticacion, expuesto, proxy, severidad):
    h = hallazgo_autenticacion(autenticacion, "detalle", expuesto, proxy, "consejo")
    assert h.id == "H2-AUTH" and h.severidad == severidad and h.evidencia == "detalle"


@pytest.mark.parametrize("valor,esperado", [
    (r"C:\modelos\a.gguf", True), ("/srv/a.gguf", True), ("~/a.gguf", True), (r"\srv\a.gguf", True), ("file:///a", True),
    ("org/modelo:Q4", False), ("alias", False), ("modelos/a.gguf", False), ("", False), (None, False),
])
def test_es_ruta_absoluta(valor, esperado):
    assert es_ruta_absoluta(valor) is esperado


def test_host_local(monkeypatch):
    monkeypatch.setattr(red, "ip_rutable", lambda: "10.1.2.3")
    assert red.es_host_local("127.0.0.1") and red.es_host_local("0.0.0.0") and red.es_host_local("10.1.2.3")
    assert not red.es_host_local("203.0.113.9")


def test_rotulo_y_url_de_un_servidor():
    assert ServidorDetectado("x", "::1", 80, prefijo="/lab").url == "http://[::1]:80/lab"
    assert texto_direccion(ServidorDetectado("x", "h", None)) == "h (puerto desconocido)"
    h = types.SimpleNamespace(evidencia="dato")
    assert rotular([h], ServidorDetectado("llama.cpp", "h", 8))[0].evidencia == "llama.cpp en h:8: dato"


def test_objetivo_malformado_no_llega_al_llamador():
    m = H2Exposicion()
    m.contexto = Contexto("linux", servidores=[servidor()])
    assert ids(m.ejecutar({"exposicion": ["no es un objeto"]})) == ["H2-ERROR"]
