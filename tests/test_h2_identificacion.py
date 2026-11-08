"""Pruebas de H2-ID: combinación de fuentes, invariantes de privacidad y de ausencia de efectos,
y el envoltorio de Julius. Son herméticas: procesos, tabla de puertos y Julius están simulados,
y las peticiones HTTP van a servidores falsos locales."""
import json
import re
import sys
import types
from pathlib import Path

import pytest

from mrrobotia import cli, nucleo
from mrrobotia.contexto import Contexto, ServidorDetectado
from mrrobotia.herramientas import Deteccion, Herramienta, Resultado, detectar
from mrrobotia.modulos import h2_identificacion as h2id
from mrrobotia.modulos.h2_identificacion import H2Identificacion, interpretar_julius
from mrrobotia.nucleo import Severidad
from mrrobotia.perfiles import PERFILES
from mrrobotia.procesos import Proceso
from servidor_falso import ServidorFalso, generico_openai, http_simple, llamacpp, vllm

CANARIO = "canario-clave-no-debe-salir"
RUTA_CANARIO = "/srv/ruta-canario/privada/modelo.gguf"


def objetivo(**extra):
    base = {"nombre": "prueba", "host": "127.0.0.1",
            "autorizacion": {"tengo_autorizacion": True, "autorizado_por": "x", "ambito": "x", "fecha": "2026-01-01"}}
    return {**base, **extra}


def proceso_llama(puerto, *extra, pid=100):
    return Proceso(pid, "llama-server", ["/opt/llama-server", "-m", RUTA_CANARIO, "--port", str(puerto), *extra])


@pytest.fixture
def entorno(monkeypatch):
    """Aísla el módulo de la máquina real. Devuelve un objeto para configurar el escenario."""
    # `julius` es la ruta simulada de Julius, o None si no está instalada.
    e = types.SimpleNamespace(procesos=[], tabla="", abiertos=set(), julius=None,
                              salida_julius="[]", ordenes_julius=[])
    monkeypatch.setattr(h2id.procesos, "enumerar", lambda: list(e.procesos))
    monkeypatch.setattr(h2id.red, "tabla_puertos", lambda: e.tabla)
    monkeypatch.setattr(h2id.red, "sondear", lambda host, puerto, timeout=2: puerto in e.abiertos)
    monkeypatch.setattr(h2id.red, "ip_rutable", lambda: None)

    def falso_detectar(herramienta, overrides=None):
        if e.julius:
            return Deteccion(True, None, e.julius, None)
        return Deteccion(False, None, None, "no encontrada en PATH")

    def falso_ejecutar(orden, timeout=600, env=None):
        e.ordenes_julius.append((orden, env))
        return Resultado(0, e.salida_julius, "", False, None)

    monkeypatch.setattr(h2id.herramientas, "detectar", falso_detectar)
    monkeypatch.setattr(h2id.herramientas, "ejecutar", falso_ejecutar)
    return e


def ejecutar(obj, activos=False, forzado=None):
    m = H2Identificacion()
    m.activos_ok = activos
    m.servidor_forzado = forzado
    return m, m.ejecutar(obj)


def ids(hallazgos):
    return [h.id for h in hallazgos]


def uno(hallazgos, id_):
    encontrados = [h for h in hallazgos if h.id == id_]
    assert len(encontrados) == 1, ids(hallazgos)
    return encontrados[0]


# ------------------------------------------------------------------- funciones puras
@pytest.mark.parametrize("ruta,esperado", [
    ("/v1/chat/completions", ""), ("/lab/v1/chat/completions", "/lab"), ("/lab", "/lab"), ("/", ""), ("", ""),
    ("/completion", ""), ("/a/b/v2/models", "/a/b"), ("/health", ""),
])
def test_prefijo_de_ruta(ruta, esperado):
    assert h2id._prefijo_de_ruta(ruta) == esperado


def test_destino_del_endpoint():
    d = h2id._destino(objetivo(endpoint="https://srv.local/lab/v1/models"))
    assert (d.esquema, d.host, d.puerto, d.prefijo) == ("https", "srv.local", 443, "/lab")


def test_destino_por_exposicion_y_sin_datos():
    d = h2id._destino(objetivo(exposicion={"puerto": 8123}))
    assert (d.host, d.puerto) == ("127.0.0.1", 8123)
    assert h2id._destino({}).puerto is None
    assert h2id._destino(objetivo(endpoint="http://[::1")).host == "127.0.0.1"


@pytest.mark.parametrize("valor,esperado", [
    ("llama.cpp", "llama.cpp"), ("LlamaCpp", "llama.cpp"), ("llama-server", "llama.cpp"), ("vLLM", "vllm"),
    ("ollama", "otro:ollama"), ("otro:lmstudio", "otro:lmstudio"), ("", None), (None, None), (5, None),
])
def test_tipo_normalizado(valor, esperado):
    assert h2id._tipo_normalizado(valor) == esperado


@pytest.mark.parametrize("valor,esperado", [
    (None, "defecto"), ("127.0.0.1", "loopback"), ("0.0.0.0", "todas"), ("10.0.0.2", ("otra", "10.0.0.2")),
    ("127.0.0.1,0.0.0.0", "todas"), ("127.0.0.1,10.0.0.2", ("otra", "10.0.0.2")),
])
def test_enlace_de_opcion(valor, esperado):
    assert h2id._enlace_de_opcion(valor, "defecto") == esperado


@pytest.mark.parametrize("valor,esperado", [(None, "127.0.0.1"), ("0.0.0.0", "127.0.0.1"), ("::1", "::1"), ("10.0.0.2", "10.0.0.2")])
def test_host_conexion(valor, esperado):
    assert h2id._host_conexion(valor) == esperado


def test_url_de_candidato_ipv6():
    assert h2id._Candidato("http", "::1", 80, "/a").url == "http://[::1]:80/a"


def test_sistema_operativo(monkeypatch):
    monkeypatch.setattr(h2id.platform, "system", lambda: "Darwin")
    assert h2id._detectar_so() == ("macos", False)


# ----------------------------------------------------------------- solo pasivo
def test_pasivo_no_toca_la_red(entorno, monkeypatch):
    entorno.procesos = [proceso_llama(8080)]
    monkeypatch.setattr(h2id.red, "ClienteHTTP", lambda *a, **k: pytest.fail("no debe crear cliente"))
    monkeypatch.setattr(h2id.red, "sondear", lambda *a, **k: pytest.fail("no debe sondear"))
    m, h = ejecutar(objetivo())
    s = m.contexto.principal()
    assert (s.tipo, s.puerto, s.confianza, s.fuentes, s.pid) == ("llama.cpp", 8080, "media", ["proceso"], 100)
    assert s.enlace == "loopback" and s.autenticacion is None and s.version is None
    assert uno(h, "H2-ID-ACTIVO-OMITIDO").severidad == Severidad.INFO
    assert uno(h, "H2-ID-SERVIDOR")


def test_enlace_real_de_la_tabla_gana_a_la_opcion(entorno):
    entorno.procesos = [proceso_llama(8080, "--host", "127.0.0.1")]
    entorno.tabla = "  TCP  0.0.0.0:8080  0.0.0.0:0  LISTENING  100\n"
    m, _ = ejecutar(objetivo())
    assert m.contexto.principal().enlace == "todas"


def test_puerto_desconocido_se_toma_de_la_tabla_por_pid(entorno):
    entorno.procesos = [Proceso(100, "llama-server", ["llama-server", "-m", "a.gguf"])]
    entorno.tabla = "  TCP  127.0.0.1:9931  0.0.0.0:0  LISTENING  100\n"
    m, _ = ejecutar(objetivo())
    assert m.contexto.principal().puerto == 9931


def test_proceso_sin_linea_legible_no_supone_enlace(entorno):
    entorno.procesos = [Proceso(100, "llama-server.exe", ["llama-server.exe"])]
    m, h = ejecutar(objetivo())
    s = m.contexto.principal()
    assert s.tipo == "llama.cpp" and s.enlace is None and s.puerto is None
    assert uno(h, "H2-ID-SERVIDOR")


def test_vllm_sin_host_escucha_en_todas(entorno):
    entorno.procesos = [Proceso(5, "vllm", ["vllm", "serve", "org/m"])]
    m, _ = ejecutar(objetivo())
    s = m.contexto.principal()
    assert (s.tipo, s.puerto, s.enlace, s.modelos) == ("vllm", 8000, "todas", ["org/m"])


def test_socket_unix_sin_puerto(entorno):
    entorno.procesos = [Proceso(5, "vllm", ["vllm", "serve", "m", "--uds", "/run/privado/v.sock"])]
    m, _ = ejecutar(objetivo())
    s = m.contexto.principal()
    assert s.puerto is None and s.enlace is None and "socket UNIX: sin puerto TCP" in s.senales
    assert s.opciones["uds"] == "v.sock"


def test_hijos_de_vllm_no_duplican_el_servidor(entorno):
    entorno.procesos = [Proceso(6, "VLLM::Worker_TP0", ["VLLM::Worker_TP0"]),
                        Proceso(5, "vllm", ["vllm", "serve", "m"]),
                        Proceso(7, "VLLM::EngineCore_DP0", ["VLLM::EngineCore_DP0"])]
    m, _ = ejecutar(objetivo())
    assert [s.pid for s in m.contexto.servidores] == [5]


def test_solo_hijos_cuentan_como_un_servidor(entorno):
    entorno.procesos = [Proceso(6, "a", ["VLLM::Worker_TP0"]), Proceso(7, "b", ["VLLM::EngineCore_DP0"])]
    m, _ = ejecutar(objetivo())
    assert len(m.contexto.servidores) == 1 and m.contexto.principal().puerto is None


def test_varios_servidores_y_entorno_linux(entorno, monkeypatch):
    entorno.procesos = [proceso_llama(1, pid=1), proceso_llama(2, pid=2)]
    monkeypatch.setattr(h2id.procesos, "leer_entorno", lambda pid, v: {"LLAMA_API_KEY": True} if pid == 2 else {})
    m, h = ejecutar(objetivo())
    assert [s.autenticacion for s in m.contexto.servidores] == [None, "activa"]
    assert ids(h).count("H2-ID-SERVIDOR") == 2


def test_host_remoto_no_inspecciona_procesos_locales(entorno, monkeypatch):
    monkeypatch.setattr(h2id.procesos, "enumerar", lambda: pytest.fail("no debe mirar procesos"))
    monkeypatch.setattr(h2id.red, "tabla_puertos", lambda: pytest.fail("no debe mirar la tabla"))
    obj = objetivo(host="203.0.113.9", endpoint="http://203.0.113.9:8000/v1/models")
    m, h = ejecutar(obj, activos=True)                          # sin confirmo_no_local
    assert m.contexto.servidores == []
    assert "confirmo_no_local" in uno(h, "H2-ID-ACTIVO-OMITIDO").evidencia


def test_todas_las_interfaces_cuenta_como_local(entorno):
    entorno.procesos = [proceso_llama(8080)]
    m, _ = ejecutar(objetivo(host="0.0.0.0"))
    assert m.contexto.principal() is not None


def test_ip_propia_cuenta_como_local(entorno, monkeypatch):
    monkeypatch.setattr(h2id.red, "ip_rutable", lambda: "10.1.2.3")
    entorno.procesos = [proceso_llama(8080)]
    m, _ = ejecutar(objetivo(host="10.1.2.3"))
    assert m.contexto.principal() is not None


# --------------------------------------------------------------- activo y combinación
def test_proceso_y_http_son_un_unico_servidor(entorno):
    with ServidorFalso(llamacpp()) as s:
        entorno.procesos = [proceso_llama(s.puerto, "--host", "127.0.0.1")]
        entorno.abiertos = {s.puerto}
        m, h = ejecutar(objetivo(endpoint=f"{s.url}/v1/chat/completions"), activos=True)
    assert len(m.contexto.servidores) == 1
    d = m.contexto.principal()
    assert (d.tipo, d.fuentes, d.confianza, d.autenticacion) == ("llama.cpp", ["proceso", "http"], "alta", "abierta")
    assert d.version == "b11583-988015788" and d.pid == 100
    assert "H2-ID-SIN-SERVIDOR" not in ids(h) and "H2-ID-ACTIVO-OMITIDO" not in ids(h)


def test_http_confirma_la_clave_del_arranque(entorno):
    with ServidorFalso(llamacpp(clave=CANARIO)) as s:
        entorno.procesos = [proceso_llama(s.puerto, "--api-key", CANARIO)]
        entorno.abiertos = {s.puerto}
        m, _ = ejecutar(objetivo(), activos=True)
    d = m.contexto.principal()
    assert (d.autenticacion, d.version) == ("activa", "b11583")


def test_http_indeterminado_no_borra_lo_que_dice_el_arranque(entorno):
    with ServidorFalso(llamacpp(clave=CANARIO, cargando=True)) as s:
        entorno.procesos = [proceso_llama(s.puerto, "--api-key", CANARIO)]
        entorno.abiertos = {s.puerto}
        m, _ = ejecutar(objetivo(), activos=True)
    assert m.contexto.principal().autenticacion == "activa"


def test_solo_http_sin_proceso(entorno):
    with ServidorFalso(vllm(clave="k")) as s:
        entorno.abiertos = {s.puerto}
        m, h = ejecutar(objetivo(endpoint=s.url + "/v1/models"), activos=True)
    d = m.contexto.principal()
    assert (d.tipo, d.fuentes, d.confianza, d.autenticacion, d.version) == ("vllm", ["http"], "alta", "activa", "0.33.0")
    assert uno(h, "H2-ID-SERVIDOR").severidad == Severidad.INFO


def test_prefijo_del_proceso_se_usa_al_preguntar(entorno):
    with ServidorFalso(llamacpp(prefijo="/lab")) as s:
        entorno.procesos = [proceso_llama(s.puerto, "--api-prefix", "/lab")]
        entorno.abiertos = {s.puerto}
        m, _ = ejecutar(objetivo(endpoint=f"{s.url}/v1/chat/completions"), activos=True)
    d = m.contexto.principal()
    assert (d.prefijo, d.autenticacion) == ("/lab", "abierta")
    assert ("GET", "/lab/props") in s.rutas()


def test_puerto_por_defecto_se_une_al_proceso_sin_puerto(entorno, monkeypatch):
    with ServidorFalso(llamacpp()) as s:
        monkeypatch.setattr(PERFILES[0], "puertos_defecto", (s.puerto,))
        entorno.procesos = [Proceso(100, "llama-server", ["llama-server", "-m", "a.gguf"])]
        entorno.abiertos = {s.puerto}
        m, _ = ejecutar(objetivo(), activos=True)
    assert len(m.contexto.servidores) == 1
    d = m.contexto.principal()
    assert (d.puerto, d.fuentes, d.confianza) == (s.puerto, ["proceso", "http"], "alta")


def test_puerto_por_defecto_cerrado_no_se_pregunta(entorno, monkeypatch):
    with ServidorFalso(llamacpp()) as s:
        monkeypatch.setattr(PERFILES[0], "puertos_defecto", (s.puerto,))
        m, h = ejecutar(objetivo(), activos=True)               # entorno.abiertos vacío
    assert s.peticiones == [] and m.contexto.servidores == []
    assert str(s.puerto) in uno(h, "H2-ID-SIN-SERVIDOR").evidencia


def test_llamacpp_no_llega_al_perfil_de_vllm(entorno):
    """El orden evita un GET /metrics, que en llama.cpp pone a cero indicadores."""
    with ServidorFalso(llamacpp()) as s:
        entorno.abiertos = {s.puerto}
        ejecutar(objetivo(endpoint=s.url), activos=True)
    assert ("GET", "/metrics") not in s.rutas() and ("GET", "/version") not in s.rutas()


def test_red_contradice_al_proceso(entorno):
    with ServidorFalso(vllm()) as s:
        entorno.procesos = [proceso_llama(s.puerto)]
        entorno.abiertos = {s.puerto}
        m, _ = ejecutar(objetivo(), activos=True)
    d = m.contexto.principal()
    assert d.tipo == "llama.cpp" and any("vllm" in x for x in d.senales) and d.confianza == "media"


def test_error_en_un_candidato_no_impide_los_demas(entorno, monkeypatch):
    with ServidorFalso(llamacpp()) as s:
        entorno.procesos = [proceso_llama(s.puerto)]
        entorno.abiertos = {s.puerto}

        def falla(cliente):
            raise RuntimeError("fallo de perfil")

        monkeypatch.setattr(PERFILES[0], "identificar_http", falla)
        m, h = ejecutar(objetivo(), activos=True)
    assert uno(h, "H2-ID-ERROR").evidencia.endswith("RuntimeError")
    assert m.contexto.principal().tipo == "llama.cpp"


def test_nunca_lanza(entorno, monkeypatch):
    def falla():
        raise RuntimeError("inesperado")

    monkeypatch.setattr(h2id.procesos, "enumerar", falla)
    m, h = ejecutar(objetivo())
    assert uno(h, "H2-ID-ERROR").severidad == Severidad.INFO and isinstance(m.contexto, Contexto)


# ------------------------------------------------------------- sin servidor y otros
def test_sin_servidor_pasivo_no_afirma_que_no_haya(entorno):
    _, h = ejecutar(objetivo())
    s = uno(h, "H2-ID-SIN-SERVIDOR")
    assert s.severidad == Severidad.INFO and "no se ha preguntado por red" in s.evidencia
    assert "no demuestra" in s.recomendacion


def test_sin_servidor_distingue_si_pudo_enumerar_procesos(entorno):
    _, h = ejecutar(objetivo())
    assert "no se pudieron enumerar los procesos" in uno(h, "H2-ID-SIN-SERVIDOR").evidencia
    entorno.procesos = [Proceso(1, "bash", ["bash"])]
    _, h = ejecutar(objetivo())
    assert "ningún proceso reconocido" in uno(h, "H2-ID-SIN-SERVIDOR").evidencia


def test_sin_servidor_activo_lista_lo_cerrado(entorno):
    _, h = ejecutar(objetivo(endpoint="http://127.0.0.1:18099/v1/models"), activos=True)
    assert "18099" in uno(h, "H2-ID-SIN-SERVIDOR").evidencia


def test_endpoint_cerrado_con_otros_servidores(entorno):
    entorno.procesos = [proceso_llama(8080)]
    _, h = ejecutar(objetivo(endpoint="http://127.0.0.1:18099/v1/models"), activos=True)
    assert uno(h, "H2-ID-SIN-SERVIDOR").titulo == "No hay servidor en el endpoint declarado"


def test_servicio_ajeno(entorno):
    with ServidorFalso(http_simple) as s:
        entorno.abiertos = {s.puerto}
        m, h = ejecutar(objetivo(endpoint=s.url), activos=True)
    assert m.contexto.servidores == []
    otro = uno(h, "H2-ID-OTRO")
    assert str(s.puerto) in otro.evidencia and "SimpleHTTP" in otro.evidencia
    assert uno(h, "H2-ID-SIN-SERVIDOR") and uno(h, "H2-ID-JULIUS-NO-INSTALADA")


def test_generico_cuando_nadie_lo_reconoce(entorno):
    with ServidorFalso(generico_openai()) as s:
        entorno.abiertos = {s.puerto}
        m, h = ejecutar(objetivo(endpoint=s.url), activos=True)
    assert (m.contexto.principal().tipo, m.contexto.principal().confianza) == ("generico", "baja")
    assert uno(h, "H2-ID-SERVIDOR").titulo.startswith("Servidor compatible")


# ------------------------------------------------------------------ Julius
SALIDA_OLLAMA = json.dumps([{
    "target": "http://x/api/tags", "service": "ollama", "matched_request": "/", "category": "self-hosted",
    "specificity": 100, "auth_required": False, "models": [RUTA_CANARIO, "llama3:8b"]}])


def test_julius_identifica_otro_servicio_antes_que_el_generico(entorno):
    entorno.julius, entorno.salida_julius = "julius-falso", SALIDA_OLLAMA
    with ServidorFalso(generico_openai()) as s:
        entorno.abiertos = {s.puerto}
        m, h = ejecutar(objetivo(endpoint=s.url), activos=True)
    d = m.contexto.principal()
    assert (d.tipo, d.fuentes, d.confianza) == ("otro:ollama", ["julius"], "media")
    assert d.modelos == ["modelo.gguf", "llama3:8b"]
    assert uno(h, "H2-ID-OTRO").titulo.endswith("ollama") and "H2-ID-SERVIDOR" not in ids(h)
    assert d.autenticacion == "indeterminada"                   # una sonda pública no lo prueba


def test_orden_de_julius(entorno, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:1")
    monkeypatch.setenv("https_proxy", "http://proxy.invalid:1")
    entorno.julius = "julius-falso"
    with ServidorFalso(http_simple) as s:
        entorno.abiertos = {s.puerto}
        ejecutar(objetivo(endpoint=f"{s.url}/lab/v1/models"), activos=True)
    orden, env = entorno.ordenes_julius[0]
    assert orden[:4] == ["julius-falso", "probe", "-o", "json"]
    assert orden[orden.index("-p") + 1] == str(h2id.DIR_SONDAS)
    assert orden[orden.index("--base-paths") + 1] == "/lab"
    assert orden[-1] == s.url                                   # siempre con esquema
    assert not {k.lower() for k in env} & {"http_proxy", "https_proxy"}


def test_julius_no_se_llama_si_un_perfil_reconoce(entorno):
    entorno.julius = "julius-falso"
    with ServidorFalso(llamacpp()) as s:
        entorno.abiertos = {s.puerto}
        ejecutar(objetivo(endpoint=s.url), activos=True)
    assert entorno.ordenes_julius == []


def test_aviso_de_julius_una_sola_vez_y_solo_si_hacia_falta(entorno):
    with ServidorFalso(llamacpp()) as s, ServidorFalso(http_simple) as ajeno, ServidorFalso(http_simple) as ajeno2:
        entorno.procesos = [proceso_llama(ajeno.puerto), proceso_llama(ajeno2.puerto, pid=2)]
        entorno.abiertos = {ajeno.puerto, ajeno2.puerto}
        _, h = ejecutar(objetivo(), activos=True)
        assert uno(h, "H2-ID-JULIUS-NO-INSTALADA").recomendacion.count("go install") == 1
        entorno.procesos, entorno.abiertos = [], {s.puerto}
        _, h = ejecutar(objetivo(endpoint=s.url), activos=True)
    assert "H2-ID-JULIUS-NO-INSTALADA" not in ids(h)


@pytest.mark.parametrize("salida", ["", "[]", "no es json", '{"a":1}', '[1,2]'])
def test_interpretar_julius_sin_resultado(salida):
    assert interpretar_julius(salida) is None


def test_interpretar_julius_descarta_la_sonda_generica():
    assert interpretar_julius('[{"service":"openai-compatible","specificity":1}]') is None


def test_interpretar_julius_elige_la_mas_especifica():
    salida = '[{"service":"llama-cpp","specificity":50},{"service":"ollama","specificity":100}]'
    assert interpretar_julius(salida).tipo == "otro:ollama"


def test_interpretar_julius_mapea_perfiles_propios():
    assert interpretar_julius('[{"service":"llama-cpp","specificity":50,"auth_required":true}]').tipo == "llama.cpp"
    assert interpretar_julius('[{"service":"vllm","specificity":75}]').tipo == "vllm"
    assert interpretar_julius('[{"service":"vllm","specificity":75,"auth_required":true}]').autenticacion == "activa"


def test_interpretar_julius_ambiguo():
    ident = interpretar_julius('[{"service":"a","specificity":50},{"service":"b","specificity":50}]')
    assert ident.confianza == "baja" and "julius ambiguo: a, b" in ident.senales


def test_detectar_sin_consultar_version():
    # El «binario» no es ejecutable: si se consultara la versión, el resultado llevaría el error.
    det = detectar(Herramienta("x", "x", version_args=None), {"x": {"ruta": "ruta-inexistente"}})
    assert (det.disponible, det.version, det.ruta, det.error) == (True, None, "ruta-inexistente", None)


# -------------------------------------------------------------- sondas de Julius
SONDAS = sorted(h2id.DIR_SONDAS.glob("*.yaml"))


def test_hay_sondas_y_las_propias_estan():
    nombres = {p.stem for p in SONDAS}
    assert len(SONDAS) > 30 and {"llama-cpp", "vllm", "ollama"} <= nombres


def test_sondas_solo_con_get():
    for sonda in SONDAS:
        lineas = sonda.read_text(encoding="utf-8").splitlines()
        metodos = [m.group(1) for m in (re.match(r"\s*(?:-\s*)?method:\s*[\"']?(\w+)", ln) for ln in lineas) if m]
        rutas = [ln for ln in lineas if re.match(r"\s*(?:-\s*)?path:", ln)]
        assert metodos and set(metodos) == {"GET"}, sonda.name
        assert len(metodos) == len(rutas), sonda.name       # sin método implícito


def test_sondas_excluidas():
    nombres = {p.stem for p in SONDAS}
    assert not nombres & {"openai-compatible", "mcp-server", "fastchat-controller", "deepspeed-mii", "aws-bedrock"}


def test_sondas_de_categorias_permitidas():
    for sonda in SONDAS:
        assert re.search(r"^category: (self-hosted|rag-orchestration)\s*$", sonda.read_text(encoding="utf-8"), re.M), sonda.name


def test_licencia_de_las_sondas():
    assert "Julius" in (h2id.DIR_SONDAS / "NOTICE").read_text(encoding="utf-8")
    assert "Apache License" in (h2id.DIR_SONDAS / "LICENSE").read_text(encoding="utf-8")


# --------------------------------------------------------- declarado y forzado
def test_conflicto_declarado_contra_detectado(entorno):
    with ServidorFalso(llamacpp()) as s:
        entorno.abiertos = {s.puerto}
        m, h = ejecutar(objetivo(endpoint=s.url, servidor="vllm"), activos=True)
    assert m.contexto.principal().tipo == "llama.cpp"           # gana lo detectado
    c = uno(h, "H2-ID-CONFLICTO")
    assert c.severidad == Severidad.MEDIA and "vllm" in c.evidencia and "llama.cpp" in c.evidencia


def test_declarado_coincide(entorno):
    with ServidorFalso(llamacpp()) as s:
        entorno.abiertos = {s.puerto}
        m, h = ejecutar(objetivo(endpoint=s.url, servidor="llama.cpp"), activos=True)
    assert m.contexto.principal().fuentes == ["http", "declarado"] and "H2-ID-CONFLICTO" not in ids(h)


def test_declarado_concreta_al_generico(entorno):
    with ServidorFalso(generico_openai()) as s:
        entorno.abiertos = {s.puerto}
        m, h = ejecutar(objetivo(endpoint=s.url, servidor="vllm"), activos=True)
    assert m.contexto.principal().tipo == "vllm" and "H2-ID-CONFLICTO" not in ids(h)


def test_declarado_sin_detectar_se_conserva_con_confianza_baja(entorno):
    m, h = ejecutar(objetivo(endpoint="http://127.0.0.1:8080/v1", servidor="llama.cpp"))
    d = m.contexto.principal()
    assert (d.tipo, d.puerto, d.confianza, d.fuentes) == ("llama.cpp", 8080, "baja", ["declarado"])
    assert "sin confirmar" in uno(h, "H2-ID-SIN-SERVIDOR").evidencia and "H2-ID-SERVIDOR" not in ids(h)


def test_declarado_con_puerto_cerrado_lo_senala(entorno):
    m, _ = ejecutar(objetivo(endpoint="http://127.0.0.1:18099/v1", servidor="llama.cpp"), activos=True)
    assert "puerto cerrado en el sondeo activo" in m.contexto.principal().senales


def test_declarado_sin_puerto_contra_lo_detectado(entorno):
    entorno.procesos = [proceso_llama(1, pid=1), proceso_llama(2, pid=2)]
    m, h = ejecutar(objetivo(servidor="vllm"))
    assert uno(h, "H2-ID-CONFLICTO") and {s.tipo for s in m.contexto.servidores} == {"llama.cpp"}


def test_declarado_sin_puerto_entre_varios_si_consta(entorno):
    entorno.procesos = [proceso_llama(1, pid=1), proceso_llama(2, pid=2)]
    _, h = ejecutar(objetivo(servidor="llama.cpp"))
    assert "H2-ID-CONFLICTO" not in ids(h)


def test_forzado_gana_y_avisa(entorno):
    with ServidorFalso(llamacpp()) as s:
        entorno.abiertos = {s.puerto}
        m, h = ejecutar(objetivo(endpoint=s.url), activos=True, forzado="vllm")
    d = m.contexto.principal()
    assert (d.tipo, d.fuentes[0], d.confianza) == ("vllm", "forzado", "alta")
    assert "Se usa lo forzado" in uno(h, "H2-ID-CONFLICTO").evidencia


def test_forzado_sin_detectar_crea_el_servidor(entorno):
    m, h = ejecutar(objetivo(endpoint="http://127.0.0.1:8080/v1"), forzado="vllm")
    d = m.contexto.principal()
    assert (d.tipo, d.fuentes, d.puerto) == ("vllm", ["forzado"], 8080)
    assert uno(h, "H2-ID-SERVIDOR") and "H2-ID-SIN-SERVIDOR" not in ids(h)


def test_forzado_no_cambia_otro_puerto(entorno):
    entorno.procesos = [proceso_llama(1, pid=1)]
    m, _ = ejecutar(objetivo(endpoint="http://127.0.0.1:8080/v1"), forzado="vllm")
    assert {(s.tipo, s.puerto) for s in m.contexto.servidores} == {("llama.cpp", 1), ("vllm", 8080)}


def test_contexto_principal_por_confianza():
    ctx = Contexto("linux", servidores=[ServidorDetectado("a", "h", 1, confianza="baja"),
                                        ServidorDetectado("b", "h", 2, confianza="alta"),
                                        ServidorDetectado("c", "h", 3, confianza="alta")])
    assert ctx.principal().tipo == "b" and Contexto("linux").principal() is None


def test_el_destino_va_primero(entorno):
    entorno.procesos = [proceso_llama(1, pid=1), proceso_llama(2, pid=2)]
    m, _ = ejecutar(objetivo(endpoint="http://127.0.0.1:2/v1"))
    assert m.contexto.principal().puerto == 2


# ---------------------------------------------------------------- informe
def _informe(obj, hallazgos, m):
    informe = nucleo.Informe(obj)
    informe.anadir(hallazgos)
    informe.contexto = m.contexto
    return informe


def test_seccion_del_informe(entorno):
    with ServidorFalso(llamacpp()) as s:
        entorno.procesos = [proceso_llama(s.puerto, "--metrics")]
        entorno.abiertos = {s.puerto}
        obj = objetivo(endpoint=f"{s.url}/v1/models")
        m, h = ejecutar(obj, activos=True)
    informe = _informe(obj, h, m)
    md = informe.to_markdown()
    assert md.index("## Qué se ha identificado") < md.index("| Severidad |")
    assert "b11583-988015788" in md and "| abierta |" in md and "metrics=presente" in md
    datos = json.loads(informe.to_json())
    assert datos["contexto"]["so"] == m.contexto.so
    assert datos["contexto"]["servidores"][0]["tipo"] == "llama.cpp"


def test_banderas_desactivadas_en_el_informe():
    informe = nucleo.Informe(objetivo())
    informe.contexto = Contexto("linux", servidores=[ServidorDetectado("vllm", "h", 1, opciones={"a": True, "b": False})])
    assert "a=presente, b=no" in informe.to_markdown()


def test_informe_sin_servidores_y_sin_contexto():
    obj = objetivo()
    informe = nucleo.Informe(obj)
    assert "Qué se ha identificado" not in informe.to_markdown()
    assert json.loads(informe.to_json())["contexto"] is None
    informe.contexto = Contexto("linux", wsl=True)
    assert "no se ha identificado ninguno" in informe.to_markdown() and "linux (WSL)" in informe.to_markdown()


def test_celdas_del_informe_escapadas():
    informe = nucleo.Informe(objetivo())
    informe.contexto = Contexto("linux", servidores=[ServidorDetectado("otro:a|b", "h", 1, opciones={"x": "a\nb"})])
    md = informe.to_markdown()
    assert "otro:a\\|b" in md and "x=a b" in md


# ------------------------------------------------- invariantes de punta a punta
def _ejecutar_cli(monkeypatch, tmp_path, obj, *extra):
    ruta = tmp_path / "objetivo.json"
    ruta.write_text(json.dumps(obj), encoding="utf-8")
    salida = tmp_path / "informe"
    monkeypatch.setattr(sys, "argv", ["mrrobotia", "--objetivo", str(ruta), "--salida", str(salida), *extra])
    cli.main()
    return Path(str(salida) + ".json").read_text(encoding="utf-8") + Path(str(salida) + ".md").read_text(encoding="utf-8")


def test_invariante_privacidad_canario_de_punta_a_punta(entorno, monkeypatch, tmp_path):
    with ServidorFalso(llamacpp(clave=CANARIO, modelo=RUTA_CANARIO)) as s:
        entorno.procesos = [Proceso(100, "llama-server", [
            r"C:\ruta-canario\llama-server.exe", "-m", RUTA_CANARIO, "--port", str(s.puerto), "--api-key", CANARIO,
            "--hf-token", CANARIO, "--mcp-servers-json", CANARIO, "-mu", f"https://u:{CANARIO}@h/m"])]
        entorno.abiertos = {s.puerto}
        monkeypatch.setattr(h2id.procesos, "leer_entorno", lambda pid, v: {"LLAMA_API_KEY": True})
        obj = objetivo(endpoint=f"{s.url}/v1/models", permitir_activos=True)
        informe = _ejecutar_cli(monkeypatch, tmp_path, obj, "--escaneo", "identificacion", "--permitir-activos")
    assert "modelo.gguf" in informe and "presente" in informe  # el informe sí dice que existen
    assert CANARIO not in informe and "ruta-canario" not in informe


def test_invariante_privacidad_con_respuesta_abierta(entorno, monkeypatch, tmp_path):
    with ServidorFalso(llamacpp(modelo=RUTA_CANARIO)) as s:
        entorno.abiertos = {s.puerto}
        obj = objetivo(endpoint=f"{s.url}/v1/models", permitir_activos=True)
        informe = _ejecutar_cli(monkeypatch, tmp_path, obj, "--escaneo", "identificacion", "--permitir-activos")
    assert "modelo.gguf" in informe and "ruta-canario" not in informe


@pytest.mark.parametrize("responder", [llamacpp(), llamacpp(clave="k"), llamacpp(webui=False, clave="k"),
                                       vllm(), vllm(clave="k"), generico_openai(), http_simple],
                         ids=["llama", "llama-clave", "llama-clave-sin-web", "vllm", "vllm-clave", "generico", "http"])
def test_invariante_sin_efectos_laterales(entorno, responder):
    with ServidorFalso(responder) as s:
        entorno.abiertos = {s.puerto}
        entorno.procesos = []
        ejecutar(objetivo(endpoint=s.url), activos=True)
    assert s.peticiones, "debe haber preguntado"
    assert {p.metodo for p in s.peticiones} <= {"GET", "HEAD", "OPTIONS"}
    assert all(p.cuerpo == b"" for p in s.peticiones)
    rutas = {p.ruta.partition("?")[0] for p in s.peticiones}
    assert not rutas & {"/slots", "/lora-adapters", "/models/sse", "/cors-proxy", "/v1/chat/completions", "/completion"}


def test_invariante_julius_solo_con_sondas_propias(entorno):
    entorno.julius = "julius-falso"
    with ServidorFalso(http_simple) as s:
        entorno.abiertos = {s.puerto}
        ejecutar(objetivo(endpoint=s.url), activos=True)
    assert all("-p" in orden for orden, _ in entorno.ordenes_julius) and entorno.ordenes_julius


# ---------------------------------------------------------------------------- CLI
def test_cli_acepta_la_etiqueta():
    assert cli._resolver_escaneo("identificacion") == ({"identificacion"}, False)


def test_cli_identifica_siempre_primero_y_pasa_el_contexto(entorno, monkeypatch, tmp_path):
    vistos = []

    class Espia(nucleo.Modulo):
        nombre, titulo, etiqueta_escaneo = "ESPIA", "t", "espia"

        def ejecutar(self, objetivo):
            vistos.append((self.contexto, self.activos_ok))
            return []

    monkeypatch.setattr(cli, "MODULOS", [Espia()])
    entorno.procesos = [proceso_llama(8080)]
    informe = _ejecutar_cli(monkeypatch, tmp_path, objetivo(), "--escaneo", "espia")
    contexto, activos = vistos[0]
    assert contexto.principal().tipo == "llama.cpp" and activos is False
    datos = json.loads(informe[:informe.index("# Informe")])
    assert datos["modulos"] == ["H2-ID", "ESPIA"] and datos["contexto"]["servidores"]


def test_cli_solo_identificacion_no_ejecuta_el_resto(entorno, monkeypatch, tmp_path):
    class Espia(nucleo.Modulo):
        nombre, titulo, etiqueta_escaneo = "ESPIA", "t", "espia"

        def ejecutar(self, objetivo):
            pytest.fail("no debe ejecutarse")

    monkeypatch.setattr(cli, "MODULOS", [Espia()])
    informe = _ejecutar_cli(monkeypatch, tmp_path, objetivo(), "--escaneo", "identificacion")
    assert '"H2-ID"' in informe


def test_cli_pasivo_no_pregunta_por_red(entorno, monkeypatch, tmp_path):
    with ServidorFalso(llamacpp()) as s:
        entorno.abiertos = {s.puerto}
        obj = objetivo(endpoint=s.url, permitir_activos=True)
        _ejecutar_cli(monkeypatch, tmp_path, obj, "--escaneo", "identificacion,pasivo", "--permitir-activos")
    assert s.peticiones == []
