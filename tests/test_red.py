"""Pruebas de `red.py`: tabla de puertos con filas reales de Windows y `ss`, y `ClienteHTTP`
contra un servidor local falso. Ninguna necesita herramientas externas."""
import gzip
import subprocess
import time
import types

import pytest

from mrrobotia import red
from mrrobotia.red import ClienteHTTP, Respuesta
from servidor_falso import ServidorFalso, desde_rutas, llamacpp

# Filas reales de `netstat -ano` en Windows en español, con los estados incoherentes
# observados en el laboratorio. El PID 4 es el del sistema.
WINDOWS = """
Conexiones activas

  Proto  Direcci�n local          Direcci�n remota        Estado           PID
  TCP    0.0.0.0:1236           0.0.0.0:0              FIN_WAIT_1      4344
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       8452
  TCP    0.0.0.0:135            0.0.0.0:0              ESCUCHANDO      1100
  TCP    127.0.0.1:18080        0.0.0.0:0              LISTENING       17712
  TCP    127.0.0.1:18080        127.0.0.1:62232        TIME_WAIT       0
  TCP    127.0.0.1:18081        0.0.0.0:0              CLOSED          18080
  TCP    127.0.0.1:62229        127.0.0.1:18080        TIME_WAIT       0
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    0.0.0.0:7000           0.0.0.0:0              LISTENING       0
  TCP    0.0.0.0:7000           0.0.0.0:0              LISTENING       900
  UDP    0.0.0.0:123            *:*                                    2044
"""

# Salida de `ss -ltnp`, con la zona de interfaz que imprime para systemd-resolved.
SS = """State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*     users:(("systemd-resolve",pid=612,fd=14))
LISTEN 0      128          0.0.0.0:22        0.0.0.0:*     users:(("sshd",pid=801,fd=3))
LISTEN 0      511        127.0.0.1:8080      0.0.0.0:*     users:(("llama-server",pid=4321,fd=3))
LISTEN 0      128             [::]:8000         [::]:*     users:(("python",pid=999,fd=12))
"""


# ------------------------------------------------------------- tabla de puertos
@pytest.mark.parametrize("linea,esperado", [
    ("  TCP    0.0.0.0:1236   0.0.0.0:0   FIN_WAIT_1   4344", True),
    ("  TCP    [::]:445       [::]:0      LISTENING    4", True),
    ("  TCP    0.0.0.0:135    0.0.0.0:0   ABHOEREN     1100", True),
    ("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*", True),
    ("tcp 0 0 127.0.0.1:8080 0.0.0.0:* LISTEN 777/llama", True),
    ("  TCP    127.0.0.1:18080   127.0.0.1:62232   TIME_WAIT   0", False),
    ("  UDP    0.0.0.0:123    *:*    2044", False),
    ("  Proto  Direccion local  Direccion remota  Estado  PID", False),
    ("", False),
])
def test_es_fila_escucha(linea, esperado):
    assert red.es_fila_escucha(linea) is esperado


def test_bind_con_estado_incoherente_de_windows():
    assert red.bind_desde_tabla(WINDOWS, 18081) == "loopback"       # estado CLOSED
    assert red.bind_desde_tabla(WINDOWS, 1236) == "todas"           # estado FIN_WAIT_1
    assert red.bind_desde_tabla(WINDOWS, 135) == "todas"            # estado traducido


def test_bind_no_se_deduce_de_filas_que_no_escuchan():
    assert red.bind_desde_tabla("  TCP  192.168.1.5:8080  10.0.0.9:50000  ESTABLISHED  77", 8080) is None
    assert red.bind_desde_tabla("  TCP  127.0.0.1:62229  127.0.0.1:18080  TIME_WAIT  0", 18080) is None


def test_bind_con_ss():
    assert red.bind_desde_tabla(SS, 53) == "loopback"
    assert red.bind_desde_tabla(SS, 22) == "todas"
    assert red.bind_desde_tabla(SS, 8080) == "loopback"
    assert red.bind_desde_tabla(SS, 8000) == "todas"


def test_pid_cero_y_cuatro_son_desconocidos():
    assert red.pid_desde_tabla(WINDOWS, 18080) == 17712
    assert red.pid_desde_tabla(WINDOWS, 445) is None
    assert red.pid_desde_tabla(WINDOWS, 7000) == 900          # el 0 no tapa la fila buena
    assert red.pid_desde_tabla(SS, 8080) == 4321


def test_puertos_en_escucha_excluye_udp_y_conexiones():
    puertos = red.puertos_en_escucha(WINDOWS)
    assert {1236, 3389, 135, 18080, 18081, 445}.issubset(puertos)
    assert 123 not in puertos and 62229 not in puertos


def test_puertos_de_pid():
    assert red.puertos_de_pid(WINDOWS, 17712) == [18080]
    assert red.puertos_de_pid(SS, 4321) == [8080]
    assert red.puertos_de_pid(SS, 1) == []


@pytest.mark.parametrize("direccion,esperado", [
    ("127.0.0.53%lo", "loopback"), ("127.1.2.3", "loopback"), ("[::1]", "loopback"),
    ("::ffff:127.0.0.1", "loopback"), ("localhost", "loopback"),
    ("0.0.0.0", "todas"), ("[::]", "todas"), ("*", "todas"),
    ("192.168.1.5", ("otra", "192.168.1.5")), ("", None),
])
def test_clasificar_direccion(direccion, esperado):
    assert red.clasificar_direccion(direccion) == esperado


@pytest.mark.parametrize("valor,esperado", [("8080", 8080), (443, 443), ("0", None), ("70000", None), ("x", None), (None, None)])
def test_a_puerto(valor, esperado):
    assert red.a_puerto(valor) == esperado


# ----------------------------------------------------------------- decodificación
def test_decodificar_nunca_lanza():
    assert red.decodificar(b"") == ""
    assert red.decodificar(None) == ""
    assert red.decodificar("á".encode("utf-8")) == "á"
    assert "Direcci" in red.decodificar("Dirección".encode("cp850"))


def test_tabla_puertos_lee_bytes_que_no_son_utf8(monkeypatch):
    def falso_run(orden, **kwargs):
        assert "text" not in kwargs             # debe leer bytes, no depender de la codificación
        return types.SimpleNamespace(
            returncode=0, stdout="  Dirección\n  TCP 0.0.0.0:80 0.0.0.0:0 LISTENING 5\n".encode("cp850"), stderr=b"")

    monkeypatch.setattr(red.subprocess, "run", falso_run)
    assert 80 in red.puertos_en_escucha(red.tabla_puertos())


def test_tabla_puertos_sin_ordenes_devuelve_vacio(monkeypatch):
    def falla(*a, **k):
        raise OSError("no existe")

    monkeypatch.setattr(red.subprocess, "run", falla)
    assert red.tabla_puertos() == ""


def test_owner_de_pid_del_sistema_no_consulta(monkeypatch):
    monkeypatch.setattr(red.subprocess, "run", lambda *a, **k: pytest.fail("no debe consultar"))
    assert red.owner_proceso(0) is None
    assert red.owner_proceso(4) is None
    assert red.owner_proceso(None) is None


def test_sondear_puerto_invalido_no_lanza():
    assert red.sondear("127.0.0.1", 70000, timeout=0.2) is False
    assert red.sondear("127.0.0.1", "x", timeout=0.2) is False


# ---------------------------------------------------------------------- Respuesta
def test_respuesta_texto_descomprime_gzip():
    r = Respuesta(200, {"content-encoding": "gzip"}, gzip.compress(b'{"a":1}'))
    assert r.texto() == '{"a":1}' and r.json() == {"a": 1}


def test_respuesta_gzip_corrupto_o_binario_no_lanza():
    assert isinstance(Respuesta(200, {"content-encoding": "gzip"}, b"\x1f\x8bbasura").texto(), str)
    assert Respuesta(200, {}, b"\xff\xfe").json() is None


def test_respuesta_bomba_gzip_queda_acotada():
    r = Respuesta(200, {"content-encoding": "gzip"}, gzip.compress(b"0" * (red.MAX_DESCOMPRIMIDO * 3)))
    assert len(r.texto()) == red.MAX_DESCOMPRIMIDO


def test_respuesta_json_invalido_es_none():
    assert Respuesta(200, {}, b"no es json").json() is None
    assert Respuesta(None, {}, b"", "error").json() is None


# -------------------------------------------------------------------- ClienteHTTP
def test_cliente_registra_y_normaliza_cabeceras():
    with ServidorFalso(llamacpp()) as s:
        c = ClienteHTTP(s.url)
        r = c.get("/health")
    assert r.estado == 200 and r.json() == {"status": "ok"}
    assert r.cabeceras["server"] == "llama.cpp"
    assert r.cabeceras["access-control-allow-origin"] == ""
    assert c.peticiones == [("GET", "/health")]


def test_cliente_gzip_solo_si_se_pide():
    with ServidorFalso(llamacpp()) as s:
        c = ClienteHTTP(s.url)
        assert c.get("/build.json").estado == 415
        r = c.get("/build.json", gzip=True)
    assert r.estado == 200 and r.json() == {"version": "b11583"}


def test_cliente_no_sigue_redirecciones():
    with ServidorFalso(desde_rutas({"GET /a": (302, {"Location": "/b"}, b"")})) as s:
        r = ClienteHTTP(s.url).get("/a")
    assert r.estado == 302 and s.rutas() == [("GET", "/a")]


def test_cliente_ignora_proxies_del_entorno(monkeypatch):
    for variable in ("HTTP_PROXY", "http_proxy", "ALL_PROXY"):
        monkeypatch.setenv(variable, "http://127.0.0.1:1")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    with ServidorFalso(llamacpp()) as s:
        assert ClienteHTTP(s.url).get("/health").estado == 200


def test_cliente_tope_de_lectura():
    grande = b"x" * (red.MAX_CUERPO * 2)
    with ServidorFalso(desde_rutas({"GET /g": (200, {}, grande)})) as s:
        r = ClienteHTTP(s.url).get("/g")
    assert len(r.cuerpo) == red.MAX_CUERPO


def test_cliente_corta_un_goteo_por_plazo_total():
    def goteo():
        for _ in range(100):
            time.sleep(0.05)
            yield b"x"

    with ServidorFalso(lambda p: (200, {}, goteo())) as s:
        inicio = time.monotonic()
        r = ClienteHTTP(s.url, timeout=0.2).get("/flujo")
    assert time.monotonic() - inicio < 2 and r.estado == 200 and 0 < len(r.cuerpo) < 100


def test_cliente_sin_servidor_no_lanza():
    with ServidorFalso(llamacpp()) as s:
        url = s.url
    r = ClienteHTTP(url, timeout=0.5).get("/health")
    assert r.estado is None and r.error and r.cuerpo == b""


@pytest.mark.parametrize("base", ["http://[::1", "", "no es una url"])
def test_cliente_url_invalida_no_lanza(base):
    r = ClienteHTTP(base, timeout=0.2).get("/x")
    assert r.estado is None and r.error


def test_cliente_antepone_prefijo_de_la_url_base():
    with ServidorFalso(llamacpp(prefijo="/lab")) as s:
        c = ClienteHTTP(s.url + "/lab/")
        assert c.get("/health").estado == 200
    assert s.rutas() == [("GET", "/lab/health")] and c.peticiones == [("GET", "/health")]


def test_cliente_envia_la_clave_y_no_la_registra():
    with ServidorFalso(llamacpp(clave="canario-clave")) as s:
        c = ClienteHTTP(s.url, clave="canario-clave")
        assert c.get("/props").estado == 200
    assert s.peticiones[0].cabeceras["authorization"] == "Bearer canario-clave"
    assert "canario-clave" not in repr(c.peticiones)


def test_cliente_options_es_preflight_cors():
    with ServidorFalso(llamacpp()) as s:
        r = ClienteHTTP(s.url).options("/health", origin="http://mrrobotia.invalid")
    assert r.estado == 200
    cabeceras = s.peticiones[0].cabeceras
    assert s.peticiones[0].metodo == "OPTIONS"
    assert cabeceras["origin"] == "http://mrrobotia.invalid"
    assert cabeceras["access-control-request-method"] == "GET"


def test_cliente_permite_host_falso():
    with ServidorFalso(llamacpp()) as s:
        ClienteHTTP(s.url).get("/props", cabeceras={"Host": "rebind.mrrobotia.invalid"})
    assert s.peticiones[0].cabeceras["host"] == "rebind.mrrobotia.invalid"


def test_cliente_head_sin_cuerpo():
    with ServidorFalso(llamacpp()) as s:
        r = ClienteHTTP(s.url).head("/health")
    assert r.estado == 200 and r.cuerpo == b"" and s.rutas() == [("HEAD", "/health")]


# ------------------------------------------------- invariante: sin efectos laterales
def test_cliente_no_expone_metodos_que_cambien_estado():
    for metodo in ("post", "put", "delete", "patch", "request"):
        assert not hasattr(ClienteHTTP, metodo)


def test_post_fuera_de_lista_blanca_no_sale():
    with ServidorFalso(llamacpp()) as s:
        c = ClienteHTTP(s.url, post_permitidos={"/slots/0?action=mrrobotia-noop"})
        for ruta in ("/v1/chat/completions", "/lora-adapters", "/slots/0?action=save"):
            with pytest.raises(ValueError):
                c.post_inocuo(ruta)
    assert s.peticiones == [] and c.peticiones == []


def test_post_inocuo_va_sin_cuerpo():
    with ServidorFalso(llamacpp()) as s:
        c = ClienteHTTP(s.url, post_permitidos={"/slots/0?action=mrrobotia-noop"})
        c.post_inocuo("/slots/0?action=mrrobotia-noop")
    p = s.peticiones[0]
    assert (p.metodo, p.ruta, p.cuerpo) == ("POST", "/slots/0?action=mrrobotia-noop", b"")


@pytest.mark.parametrize("ruta", ["/models/sse", "/models/sse?x=1", "/cors-proxy?url=http://127.0.0.1:1/"])
def test_rutas_vetadas_no_salen(ruta):
    with ServidorFalso(llamacpp()) as s:
        c = ClienteHTTP(s.url)
        respuestas = [c.get(ruta), c.head(ruta)]
    assert all(r.estado is None for r in respuestas) and s.peticiones == [] and c.peticiones == []


def test_cors_proxy_sin_url_sigue_permitido():
    with ServidorFalso(llamacpp()) as s:
        ClienteHTTP(s.url).get("/cors-proxy")
    assert s.rutas() == [("GET", "/cors-proxy")]


def test_subprocess_no_usa_shell(monkeypatch):
    llamadas = []

    def falso_run(orden, **kwargs):
        llamadas.append((orden, kwargs))
        return subprocess.CompletedProcess(orden, 0, b"", b"")

    monkeypatch.setattr(red.subprocess, "run", falso_run)
    red.tabla_puertos()
    assert llamadas and all(isinstance(o, list) and "shell" not in k for o, k in llamadas)
