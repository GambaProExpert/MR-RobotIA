"""Pruebas herméticas de H6-SALIDAS: parsers de tablas de sockets, clasificación, observación con fuentes inyectadas,
síntesis, auditoría estática de canales y una integración con un servidor falso. No sale nada de la máquina."""
import json
import os
import re
import socket
import struct
import threading
from pathlib import Path

import pytest

from mrrobotia import nucleo, procesos, red
from mrrobotia.contexto import Contexto, ServidorDetectado
from mrrobotia.modulos import h6_salidas as h6
from mrrobotia.nucleo import Informe, Severidad
from mrrobotia.perfiles import PERFILES
from mrrobotia.perfiles import vllm as perfil_vllm
from mrrobotia.red import Fila
from servidor_falso import ServidorFalso

FIX = Path(__file__).parent / "fixtures" / "h6"
VLLM, LLAMA = PERFILES[1], PERFILES[0]
EXTERNA = "93.184.216.34"      # solo se usa como texto: ninguna prueba conecta a ella


def leer(nombre):
    return (FIX / nombre).read_text(encoding="ascii")


def servidor(tipo="vllm", **kw):
    return ServidorDetectado(**{"tipo": tipo, "host": "127.0.0.1", "puerto": 8000, "fuentes": ["http"],
                                "enlace": "loopback", **kw})


def fila(local="10.0.0.2", puerto_local=50000, remota=EXTERNA, puerto=443, estado="ESTABLISHED", pid=10, proto="tcp"):
    return Fila(proto, local, puerto_local, remota, puerto, estado, pid)


# ------------------------------------------------------------------------------------------------ parsers
def _ipv4(estado, la, lp, ra, rp, pid):
    return struct.pack("<IIIIII", estado, struct.unpack("<I", socket.inet_aton(la))[0], socket.htons(lp),
                       struct.unpack("<I", socket.inet_aton(ra))[0], socket.htons(rp), pid)


def _ipv6(la, lp, ra, rp, estado, pid):
    return (socket.inet_pton(socket.AF_INET6, la) + struct.pack("<II", 0, socket.htons(lp))
            + socket.inet_pton(socket.AF_INET6, ra) + struct.pack("<IIIII", 0, socket.htons(rp), estado, pid, 0))[:56]


def test_tabla_windows_ipv4():
    datos = struct.pack("<I", 3) + _ipv4(2, "0.0.0.0", 8000, "0.0.0.0", 0, 100) + _ipv4(
        5, "10.0.0.2", 50000, EXTERNA, 443, 100) + _ipv4(11, "10.0.0.2", 50001, EXTERNA, 443, 0)
    escucha, viva, espera = red.filas_tabla_tcp_todas(datos, socket.AF_INET)
    assert (escucha.estado, escucha.puerto_local, escucha.pid) == ("LISTEN", 8000, 100)
    assert (viva.remota, viva.puerto_remoto, viva.estado, viva.pid, viva.local) == (EXTERNA, 443, "ESTABLISHED", 100, "10.0.0.2")
    assert (espera.estado, espera.pid) == ("TIME_WAIT", 0)


def test_tabla_windows_ipv6():
    datos = struct.pack("<I", 1) + _ipv6("fd00::2", 51000, "2001:db8::1", 443, 3, 77)
    assert len(datos) == 4 + 56
    (f,) = red.filas_tabla_tcp_todas(datos, socket.AF_INET6)
    assert (f.local, f.puerto_local, f.remota, f.puerto_remoto, f.estado, f.pid) == (
        "fd00::2", 51000, "2001:db8::1", 443, "SYN_SENT", 77)


def test_tabla_windows_corrupta_no_lanza():
    assert red.filas_tabla_tcp_todas(b"\x05\x00\x00\x00abc", socket.AF_INET) == []
    assert red.filas_tabla_tcp_todas(b"", socket.AF_INET) == []


def test_proc_net_tcp_real():
    filas = red.filas_proc_net(leer("proc_net_tcp_conexiones.txt"), "tcp", {"10437": 55, "11972": 55, "11974": 55})
    syn = [f for f in filas if f.estado == "SYN_SENT"]
    assert len(syn) == 1
    assert (syn[0].remota, syn[0].puerto_remoto, syn[0].pid) == ("172.23.223.250", 443, 55)
    escucha = [f for f in filas if f.estado == "LISTEN" and f.pid == 55]
    assert [f.puerto_local for f in escucha] == [0x49C8]
    assert any(f.pid is None for f in filas)            # sockets de otros procesos: no atribuidos


def test_proc_net_ipv6_y_udp_real():
    (f6,) = red.filas_proc_net(leer("proc_net_tcp6_conexiones.txt"), "tcp6", {})
    assert (f6.local, f6.estado, f6.proto) == ("::1", "LISTEN", "tcp")
    udp = red.filas_proc_net(leer("proc_net_udp_conexiones.txt"), "udp", {"11976": 9})
    conectado = [f for f in udp if f.estado == "UDP_CONECTADO"]
    assert [(f.remota, f.puerto_remoto, f.pid) for f in conectado] == [("172.23.223.250", 53, 9)]
    assert {f.estado for f in udp} == {"UDP", "UDP_CONECTADO"}


def test_proc_net_time_wait_sin_inodo():
    texto = "sl\n 0: 0100007F:1F40 0100007F:D9F6 06 00000000:00000000 00:00000000 00000000 0 0 0 1 0 0 0 0\n"
    (f,) = red.filas_proc_net(texto, "tcp", {})
    assert (f.estado, f.pid) == ("TIME_WAIT", 0)


def test_sockets_reales_ven_un_socket_propio():
    """El lector real de la plataforma ve el socket que acabamos de abrir (en Windows o Linux)."""
    escucha = socket.socket()
    escucha.bind(("127.0.0.1", 0))
    escucha.listen(1)
    try:
        puerto = escucha.getsockname()[1]
        if os.name == "nt":
            filas = red.sockets_windows()
        else:
            filas, _ = red.sockets_linux({os.getpid()})
        assert any(f.puerto_local == puerto and f.estado == "LISTEN" and f.pid == os.getpid() for f in filas)
    finally:
        escucha.close()


def test_tabla_de_procesos_real_incluye_este_proceso():
    tabla = procesos.tabla_pid_ppid()
    assert os.getpid() in tabla and isinstance(tabla[os.getpid()][1], str)


def test_arbol_de_sigue_hijos_y_resiste_ciclos():
    tabla = {1: (0, "a"), 2: (1, "b"), 3: (2, "c"), 4: (9, "x"), 5: (6, "p"), 6: (5, "q")}
    assert procesos.arbol_de(tabla, [1]) == {1, 2, 3}
    assert procesos.arbol_de(tabla, [5]) == {5, 6}
    assert procesos.arbol_de(tabla, [99]) == set()


# ------------------------------------------------------------------------------------------------ clasificar
def clase(f, escucha=(8000,), propias=("10.0.0.2",), permitidas=(), api=8000):
    return h6.clasificar(f, set(escucha), set(propias), permitidas, api)


@pytest.mark.parametrize("remota,esperada", [
    ("127.0.0.1", "propia"), ("::1", "propia"), ("::ffff:127.0.0.1", "propia"), ("10.0.0.2", "propia"),
    (EXTERNA, "SALIDA"), ("10.9.9.9", "SALIDA"), ("fd00::9", "SALIDA")])
def test_clasificar_destinos(remota, esperada):
    assert clase(fila(remota=remota)) == esperada


def test_clasificar_escucha_entrante_y_pull():
    assert clase(fila(estado="LISTEN", remota="0.0.0.0", puerto=0)) == "escucha"
    assert clase(fila(proto="udp", estado="UDP", remota=None, puerto=None)) == "escucha"
    assert clase(fila(puerto_local=8000, remota="127.0.0.1", puerto=51000)) == "entrante"
    assert clase(fila(puerto_local=8000, remota="192.168.1.50", puerto=51000)) == "entrante"        # cliente de la API
    assert clase(fila(puerto_local=5557, remota="192.168.1.50", puerto=51000), escucha=(8000, 5557)) == "pull"
    assert clase(fila(puerto_local=5557, remota="127.0.0.1", puerto=51000), escucha=(8000, 5557)) == "entrante"


def test_clasificar_permitidas():
    reglas, _, error = h6.parsear_permitidas(["10.0.0.0/8", "172.16.0.9:8092", "[fd00::1]:50052", "93.184.216.34"])
    assert error is None
    assert clase(fila(remota="10.4.4.4"), permitidas=reglas) == "permitida"
    assert clase(fila(remota="172.16.0.9", puerto=8092), permitidas=reglas) == "permitida"
    assert clase(fila(remota="172.16.0.9", puerto=9999), permitidas=reglas) == "SALIDA"
    assert clase(fila(remota="fd00::1", puerto=50052), permitidas=reglas) == "permitida"
    assert clase(fila(remota=EXTERNA), permitidas=reglas) == "permitida"


def test_clasificar_dns_udp_y_get_ip_de_vllm():
    assert clase(fila(proto="udp", estado="UDP_CONECTADO", remota="9.9.9.9", puerto=53)) == "SALIDA_DNS"
    assert clase(fila(proto="udp", estado="UDP_CONECTADO", remota="8.8.8.8", puerto=80)) == "ignorada"
    assert clase(fila(proto="udp", estado="UDP_CONECTADO", remota="2001:4860:4860::8888", puerto=80)) == "ignorada"
    assert clase(fila(proto="udp", estado="UDP_CONECTADO", remota="9.9.9.9", puerto=443)) == "SALIDA_UDP"


def test_clasificar_time_wait_sin_pid_se_ignora():
    assert clase(fila(estado="TIME_WAIT", pid=0)) == "ignorada"
    assert clase(fila(pid=None)) == "ignorada"


@pytest.mark.parametrize("ip,sub", [("10.1.1.1", "privada"), ("172.16.5.5", "privada"), ("192.168.0.4", "privada"),
                                    ("100.64.1.1", "privada"), ("fc00::1", "privada"), ("fe80::1", "privada"),
                                    (EXTERNA, "publica"), ("2606:4700::1", "publica")])
def test_subclase(ip, sub):
    assert h6.subclase_de(ip) == sub


def test_allow_con_nombre_se_resuelve_una_vez():
    llamadas = []
    reglas, nombres, error = h6.parsear_permitidas(
        ["pasarela.local"], lambda n, p: llamadas.append(n) or [(0, 0, 0, "", ("10.1.2.3", 0))])
    assert error is None and nombres == ["pasarela.local"] and llamadas == ["pasarela.local"] and len(reglas) == 1

    def falla(n, p):
        raise OSError()
    assert h6.parsear_permitidas(["no es nada ???"], falla)[2]
    assert h6.parsear_permitidas(["10.0.0.1:99999"])[2]


# ------------------------------------------------------------------------------------------------ observar
class Reloj:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def dormir(self, s):
        self.t += s


def observar_guion(guion, **kw):
    """`guion`: lista de (tabla_procesos, filas) por muestra; la última se repite."""
    reloj, i = Reloj(), [0]

    def procesos_():
        return guion[min(i[0], len(guion) - 1)][0]

    def sockets(pids):
        f = guion[min(i[0], len(guion) - 1)][1]
        i[0] += 1
        return f, False
    args = dict(raices=[10], segundos=1.0, intervalo=0.1, reloj=reloj, dormir=reloj.dormir, leer_procesos=procesos_,
                leer_sockets=sockets, puerto_api=8000)
    args.update(kw)
    return h6.observar(args.pop("raices"), args.pop("segundos"), args.pop("intervalo"), **args)


ESCUCHA = fila(local="0.0.0.0", puerto_local=8000, remota="0.0.0.0", puerto=0, estado="LISTEN")


def test_observar_un_hijo_que_aparece_entra_en_el_arbol():
    t1 = {10: (1, "vllm"), 99: (1, "otro")}
    t2 = {**t1, 11: (10, "VLLM::EngineCore")}
    sale = fila(pid=11, estado="SYN_SENT")
    ajena = fila(pid=99, remota="198.51.100.9")
    obs = observar_guion([(t1, [ESCUCHA, ajena]), (t2, [ESCUCHA, ajena, sale])])
    assert 11 in obs.pids and 99 not in obs.pids
    (c,) = obs.conexiones
    assert (c["pid"], c["remota"], c["puerto"], c["clase"], c["subclase"]) == (11, EXTERNA, 443, "SALIDA", "publica")
    assert c["primera_s"] == 0.1 and c["proceso"] == "VLLM::EngineCore"


def test_observar_una_conexion_vista_varias_veces_cuenta_una():
    t = {10: (1, "llama-server")}
    pasos = [[fila(estado="SYN_SENT")], [fila(estado="ESTABLISHED")], [fila(estado="ESTABLISHED")],
             [fila(estado="FIN_WAIT1")]]
    obs = observar_guion([(t, p + [ESCUCHA]) for p in pasos])
    (c,) = obs.conexiones
    assert c["estados"] == ["ESTABLISHED", "FIN_WAIT1", "SYN_SENT"] and c["n"] == 1 and c["inicios"] == [0.0]
    assert obs.clases["SALIDA"] >= 4


def test_observar_cuenta_puertos_locales_distintos_y_time_wait_se_ignora():
    t = {10: (1, "llama-server")}
    filas = [ESCUCHA, fila(puerto_local=50001), fila(puerto_local=50002),
             fila(estado="TIME_WAIT", pid=0, puerto_local=50003)]
    obs = observar_guion([(t, filas)], segundos=0.0)
    (c,) = obs.conexiones
    assert c["n"] == 2 and len(c["inicios"]) == 2


def test_observar_loopback_entrante_y_propia_no_son_salida():
    t = {10: (1, "llama-server")}
    filas = [ESCUCHA, fila(puerto_local=8000, remota="127.0.0.1", puerto=51000), fila(remota="127.0.0.1", puerto=9),
             fila(remota="10.0.0.2", puerto=22)]
    obs = observar_guion([(t, filas)], segundos=0.0)
    assert obs.conexiones == [] and obs.clases["entrante"] == 1 and obs.clases["propia"] == 2


def test_observar_propias_salen_de_la_tabla_del_sistema():
    """Una conexión a la IP de LAN del propio equipo (aparece como dirección local de otra fila) no es salida."""
    t = {10: (1, "llama-server")}
    otra = fila(local="192.168.7.7", pid=500, remota="192.168.7.8", puerto=22)
    mia = fila(remota="192.168.7.7", puerto=8000)
    obs = observar_guion([(t, [ESCUCHA, otra, mia])], segundos=0.0)
    assert obs.conexiones == []


def test_observar_sin_proceso_no_inventa_nada():
    obs = observar_guion([({}, [])], segundos=0.3)
    assert obs.pids == {} and obs.conexiones == [] and obs.muestras >= 3


def test_observar_se_para_con_el_evento_y_por_nombre():
    parar = threading.Event()
    parar.set()
    t = {7: (1, "pasarela.exe"), 8: (7, "hijo")}
    obs = observar_guion([(t, [fila(pid=8)])], raices=[], nombres=["Pasarela.EXE"], segundos=99, parar=parar)
    assert obs.muestras == 1 and set(obs.pids) == {7, 8} and len(obs.conexiones) == 1


def test_observar_tope_de_conexiones(monkeypatch):
    monkeypatch.setattr(h6, "MAX_CONEXIONES", 3)
    t = {10: (1, "x")}
    filas = [fila(remota=f"93.184.216.{i}") for i in range(10)]
    obs = observar_guion([(t, filas)], segundos=0.0)
    assert len(obs.conexiones) == 3 and obs.truncada


def test_observar_pull_y_dns_y_udp():
    t = {10: (1, "vllm")}
    filas = [ESCUCHA, fila(puerto_local=5557, remota="192.168.1.50", puerto=40000, estado="ESTABLISHED"),
             fila(local="0.0.0.0", puerto_local=5557, remota="0.0.0.0", puerto=0, estado="LISTEN"),
             fila(proto="udp", estado="UDP_CONECTADO", remota="9.9.9.9", puerto=53),
             fila(proto="udp", estado="UDP_CONECTADO", remota="8.8.8.8", puerto=80)]
    obs = observar_guion([(t, filas)], segundos=0.0)
    assert sorted(c["clase"] for c in obs.conexiones) == ["SALIDA_DNS", "pull"]


# ------------------------------------------------------------------------------------------------ síntesis
def conexion(remota=EXTERNA, puerto=443, clase="SALIDA", sub=None, inicios=(1.4,), ventana="activa", pid=10, n=None):
    return {"clase": clase, "subclase": sub or h6.subclase_de(remota), "proto": "tcp", "pid": pid, "proceso": "vllm",
            "remota": remota, "puerto": puerto, "estados": ["SYN_SENT"], "primera_s": inicios[0],
            "ultima_s": inicios[-1], "inicios": list(inicios), "n": n or len(inicios), "ventana": ventana}


def obs(conexiones, ventana="activa", pids=None, **kw):
    return h6.Observacion(muestras=100, segundos=30, coste_ms=8, pids=pids or {10: "vllm"}, conexiones=conexiones,
                          ventana=ventana, **kw)


META = {"intervalo_ms": 100, "correlacion_s": 5.0, "puertos_internos": {5557: "eventos KV (ZMQ)"}}


def sintetizar(pasiva=None, activa=None, envios=()):
    hs, filas, hay = h6.hallazgos_desde_observacion(pasiva, activa, list(envios), META)
    return {h.id: h for h in hs}, filas, hay


def test_salida_publica_en_reposo_es_alta():
    hs, filas, hay = sintetizar(pasiva=obs([conexion(ventana="pasiva", inicios=(2.0,))], "pasiva"))
    h = hs["H6-SALIDAS-CONEXION-1"]
    assert (h.severidad, h.estado) == (Severidad.ALTA, "confirmado") and hay
    assert "tcp 93.184.216.34:443" in h.evidencia and "PID 10 (vllm)" in h.evidencia and "pasiva" in h.evidencia
    assert filas[0]["clase"] == "publica"


def test_correlacion_critica_con_peticiones_y_salidas_nuevas():
    envios = [(1.0, True), (7.0, True), (13.0, True)]
    activa = obs([conexion(inicios=(1.4, 7.3, 13.2))])
    hs, _, _ = sintetizar(pasiva=obs([], "pasiva"), activa=activa, envios=envios)
    c = hs["H6-SALIDAS-CORRELACION"]
    assert c.severidad == Severidad.CRITICA and "3 de 3" in c.evidencia
    assert "tras la petición 1" in hs["H6-SALIDAS-CONEXION-1"].evidencia


def test_sin_correlacion_si_la_salida_ya_estaba_en_reposo():
    envios = [(1.0, True), (7.0, True), (13.0, True)]
    pasiva = obs([conexion(ventana="pasiva", inicios=(3.0,))], "pasiva")
    activa = obs([conexion(inicios=(1.4, 7.3, 13.2))])
    hs, _, _ = sintetizar(pasiva, activa, envios)
    assert "H6-SALIDAS-CORRELACION" not in hs and hs["H6-SALIDAS-CONEXION-1"].severidad == Severidad.ALTA


def test_sin_correlacion_si_solo_una_peticion_la_provoca():
    envios = [(1.0, True), (7.0, True), (13.0, True), (19.0, True)]
    hs, _, _ = sintetizar(activa=obs([conexion(inicios=(1.4,))]), envios=envios)
    assert "H6-SALIDAS-CORRELACION" not in hs and hs["H6-SALIDAS-CONEXION-1"].severidad == Severidad.ALTA


def test_salida_privada_es_media_y_alta_si_se_correlaciona():
    hs, _, _ = sintetizar(pasiva=obs([conexion("10.9.9.9", ventana="pasiva", inicios=(2.0,))], "pasiva"))
    assert hs["H6-SALIDAS-CONEXION-1"].severidad == Severidad.MEDIA
    envios = [(1.0, True), (7.0, True)]
    hs, _, _ = sintetizar(activa=obs([conexion("10.9.9.9", inicios=(1.2, 7.2))]), envios=envios)
    assert hs["H6-SALIDAS-CONEXION-1"].severidad == Severidad.ALTA and "H6-SALIDAS-CORRELACION" not in hs


def test_dns_udp_y_pull():
    hs, _, _ = sintetizar(pasiva=obs([
        conexion("9.9.9.9", 53, "SALIDA_DNS", ventana="pasiva"), conexion("9.9.9.9", 443, "SALIDA_UDP", ventana="pasiva"),
        conexion("192.168.1.50", 5557, "pull", ventana="pasiva"),
        conexion("192.168.1.51", 7777, "pull", ventana="pasiva")], "pasiva"))
    assert hs["H6-SALIDAS-DNS"].severidad == Severidad.BAJA
    assert [h.severidad for i, h in hs.items() if i.startswith("H6-SALIDAS-UDP")] == [Severidad.MEDIA]
    assert hs["H6-SALIDAS-PULL-5557"].severidad == Severidad.ALTA and hs["H6-SALIDAS-PULL-7777"].severidad == Severidad.MEDIA


def test_sin_permiso():
    hs, _, _ = sintetizar(pasiva=obs([], "pasiva", sin_permiso=True))
    assert hs["H6-SALIDAS-SIN-PERMISO"].estado == "sin_concluir"


# ------------------------------------------------------------------------------------------------ auditoría estática
def canales(s, expuesto=False, **cfg):
    c = h6.validar_config(cfg or None)[0]
    hs, tabla = h6.auditar_canales(s, c, expuesto)
    return {h.id: h for h in hs}, tabla


def test_do_not_track_true_no_vale_y_1_si():
    """Antes del arreglo, perfiles/vllm.py daba por buena cualquier valor: DO_NOT_TRACK=true pasaba por «excluido»."""
    assert perfil_vllm.exclusion_telemetria({"DO_NOT_TRACK": "true"}) == ("invalida", "DO_NOT_TRACK")
    assert perfil_vllm.exclusion_telemetria({"DO_NOT_TRACK": "1"}) == ("valida", "DO_NOT_TRACK")
    assert perfil_vllm.exclusion_telemetria({"VLLM_NO_USAGE_STATS": "1", "DO_NOT_TRACK": "true"})[0] == "valida"
    assert perfil_vllm.exclusion_telemetria({"VLLM_DO_NOT_TRACK": "yes"})[0] == "invalida"
    assert perfil_vllm.exclusion_telemetria({"DO_NOT_TRACK": ""})[0] == "ausente"
    assert perfil_vllm.exclusion_telemetria({})[0] == "ausente"
    hs, _ = canales(servidor(entorno={"DO_NOT_TRACK": "true"}))
    h = hs["H6-SALIDAS-CANAL-TELEMETRIA-EXCLUSION-INVALIDA"]
    assert h.severidad == Severidad.BAJA and h.estado == "confirmado"
    assert "H6-SALIDAS-CANAL-TELEMETRIA" not in hs


@pytest.mark.parametrize("variable", ["VLLM_NO_USAGE_STATS", "VLLM_DO_NOT_TRACK", "DO_NOT_TRACK"])
def test_telemetria_cerrada_con_1(variable):
    hs, tabla = canales(servidor(entorno={variable: "1", "VLLM_LOGGING_LEVEL": "INFO"}))
    assert not [i for i in hs if "TELEMETRIA" in i]
    assert next(t for t in tabla if t["canal"] == "TELEMETRIA")["estado"] == "cerrado"


def test_telemetria_abierta_baja_y_en_cpu_info():
    hs, _ = canales(servidor(entorno={"VLLM_LOGGING_LEVEL": "INFO"}))
    h = hs["H6-SALIDAS-CANAL-TELEMETRIA"]
    assert (h.severidad, h.estado) == (Severidad.BAJA, "confirmado") and "no prompts" in h.evidencia
    hs, _ = canales(servidor(entorno={"VLLM_LOGGING_LEVEL": "INFO"}, version="0.33.0+cpu"))
    assert hs["H6-SALIDAS-CANAL-TELEMETRIA"].severidad == Severidad.INFO


def test_telemetria_sin_entorno_legible_no_afirma(monkeypatch):
    monkeypatch.setattr(procesos, "entorno_legible", lambda pid: False)
    monkeypatch.setattr(procesos, "leer_entorno", lambda pid, v: {})
    hs, tabla = canales(servidor(pid=5))
    h = hs["H6-SALIDAS-CANAL-TELEMETRIA"]
    assert h.estado == "sin_concluir" and "no es legible" in h.evidencia and "envía" not in h.titulo
    assert next(t for t in tabla if t["canal"] == "TELEMETRIA")["estado"] == "sin comprobar"


def test_telemetria_con_entorno_vacio_pero_legible(monkeypatch):
    monkeypatch.setattr(procesos, "entorno_legible", lambda pid: True)
    monkeypatch.setattr(procesos, "leer_entorno", lambda pid, v: {})
    hs, _ = canales(servidor(pid=5))
    assert hs["H6-SALIDAS-CANAL-TELEMETRIA"].estado == "confirmado"


def test_fichero_do_not_track_cierra_el_canal(tmp_path):
    (tmp_path / "do_not_track").write_text("")
    hs, _ = canales(servidor(entorno={"VLLM_CONFIG_ROOT": str(tmp_path)}))
    assert "H6-SALIDAS-CANAL-TELEMETRIA" not in hs


def test_historial_usage_stats(tmp_path):
    (tmp_path / "usage_stats.json").write_text(
        json.dumps({"uuid": "x", "log_time": "2026-01-01T10:00:00"}) + "\n"
        + json.dumps({"log_time": "2026-01-01T10:10:00"}) + "\n")
    hs, _ = canales(servidor(entorno={"VLLM_CONFIG_ROOT": str(tmp_path), "VLLM_NO_USAGE_STATS": "1"}))
    h = hs["H6-SALIDAS-CANAL-TELEMETRIA-HISTORIAL"]
    assert "2 línea(s)" in h.evidencia and "10:10:00" in h.evidencia and h.severidad == Severidad.BAJA
    hs, _ = canales(servidor(entorno={"VLLM_CONFIG_ROOT": str(tmp_path)}), history_files=False)
    assert "H6-SALIDAS-CANAL-TELEMETRIA-HISTORIAL" not in hs


def test_hub_en_linea_con_y_sin_offline():
    s = servidor(opciones=VLLM.analizar_argv(["vllm", "serve", "org/modelo"]), entorno={"VLLM_NO_USAGE_STATS": "1"})
    assert s.opciones["model_remoto"] is True
    h = canales(s)[0]["H6-SALIDAS-CANAL-HUB"]
    assert h.severidad == Severidad.BAJA and "huggingface.co" in h.evidencia
    cerrado = servidor(opciones=s.opciones, entorno={"VLLM_NO_USAGE_STATS": "1", "HF_HUB_OFFLINE": "1"})
    assert "H6-SALIDAS-CANAL-HUB" not in canales(cerrado)[0]


def test_ruta_local_no_es_hub():
    assert "model_remoto" not in VLLM.analizar_argv(["vllm", "serve", "/srv/modelos/org/m"])
    assert "model_remoto" not in VLLM.analizar_argv(["vllm", "serve", "C:\\modelos\\m"])
    assert "model_remoto" not in VLLM.analizar_argv(["vllm", "serve", "./org/m"])


def test_kv_eventos_zmq():
    cfg = json.dumps({"enable_kv_cache_events": True, "publisher": "zmq", "endpoint": "tcp://*:5557"})
    s = servidor(opciones={"kv_events_config": cfg}, entorno={"VLLM_NO_USAGE_STATS": "1"})
    assert canales(s)[0]["H6-SALIDAS-CANAL-KV-EVENTOS"].severidad == Severidad.ALTA
    expuesto = servidor(opciones={"kv_events_config": cfg}, entorno={"VLLM_NO_USAGE_STATS": "1"}, enlace="todas")
    assert canales(expuesto, expuesto=True)[0]["H6-SALIDAS-CANAL-KV-EVENTOS"].severidad == Severidad.CRITICA
    nulo = servidor(opciones={"kv_events_config": json.dumps({"enable_kv_cache_events": True, "publisher": "null"})})
    assert "H6-SALIDAS-CANAL-KV-EVENTOS" not in canales(nulo)[0]


def test_trazas_otlp_local_o_remota():
    local = canales(servidor(opciones={"otlp_traces_endpoint": "http://localhost:4317"}))[0]["H6-SALIDAS-CANAL-TRAZAS"]
    remota = canales(servidor(opciones={"otlp_traces_endpoint": "https://otel.ejemplo.net:4317"}))[0]["H6-SALIDAS-CANAL-TRAZAS"]
    assert (local.severidad, remota.severidad) == (Severidad.INFO, Severidad.MEDIA)


def test_kv_transfer_y_herramientas():
    hs, _ = canales(servidor(opciones={"kv_transfer_config": True, "tool_server": "10.1.1.1:8080"}))
    assert hs["H6-SALIDAS-CANAL-KV-TRANSFER"].severidad == Severidad.MEDIA
    assert hs["H6-SALIDAS-CANAL-MCP"].severidad == Severidad.ALTA
    assert "H6-SALIDAS-CANAL-MCP" not in canales(servidor(opciones={"tool_server": "demo"}))[0]


def test_llamacpp_descarga_con_y_sin_offline_y_rpc():
    s = servidor("llama.cpp", opciones={"hf_repo": "org/m", "rpc": True})
    hs, tabla = canales(s)
    assert hs["H6-SALIDAS-CANAL-DESCARGA"].severidad == Severidad.BAJA
    assert hs["H6-SALIDAS-CANAL-RPC"].severidad == Severidad.ALTA
    assert next(t for t in tabla if t["canal"] == "TELEMETRIA")["estado"] == "cerrado"
    sin = servidor("llama.cpp", opciones={"hf_repo": "org/m", "offline": True})
    assert "H6-SALIDAS-CANAL-DESCARGA" not in canales(sin)[0]
    por_env = servidor("llama.cpp", opciones={"hf_repo": "org/m"}, entorno={"LLAMA_ARG_OFFLINE": "1"})
    assert "H6-SALIDAS-CANAL-DESCARGA" not in canales(por_env)[0]


def test_llamacpp_opciones_nuevas_se_analizan():
    o = LLAMA.analizar_argv(["llama-server", "--offline", "-hfd", "org/d", "--mcp-servers-json", '{"clave":"secreto-x"}',
                             "--rpc", "10.0.0.2:50052"])
    assert o["offline"] is True and o["hf_repo_draft"] == "org/d" and o["mcp_servers_json"] is True and o["rpc"] is True
    hs, _ = canales(servidor("llama.cpp", opciones=o))
    assert "H6-SALIDAS-CANAL-MCP" in hs and "secreto-x" not in repr(hs)


def test_proxy_en_el_entorno_no_guarda_el_valor():
    hs, _ = canales(servidor(entorno={"HTTPS_PROXY": True, "VLLM_NO_USAGE_STATS": "1"}))
    assert hs["H6-SALIDAS-CANAL-PROXY"].severidad == Severidad.INFO and "user" not in hs["H6-SALIDAS-CANAL-PROXY"].evidencia


def test_opciones_de_h6_no_filtran_secretos():
    o = VLLM.analizar_argv(["vllm", "serve", "m", "--kv-transfer-config", '{"kv_ip":"10.9.9.9"}',
                            "--otlp-traces-endpoint", "http://u:clave@h:4317"])
    assert o["kv_transfer_config"] is True and o["otlp_traces_endpoint"] is True and "10.9.9.9" not in repr(o)


# ------------------------------------------------------------------------------------------------ configuración
def test_config_por_defecto_y_rangos():
    cfg, error = h6.validar_config(None)
    assert error is None and (cfg["passive_window"], cfg["active_window"], cfg["interval_ms"], cfg["canaries"]) == (10, 30, 100, 5)
    assert cfg["canary_endpoint"] == "chat" and cfg["history_files"] is True
    for malo in ({"pasive_window": 3}, {"passive_window": 601}, {"interval_ms": 10}, {"canaries": 0}, {"canaries": 2.5},
                 {"canary_endpoint": "x"}, {"api_key_env": "mi clave"}, {"allow": [""]}, {"pids": [0]},
                 {"history_files": 1}, {"correlation_s": True}, [], "x"):
        assert h6.validar_config(malo)[1], malo
    assert h6.validar_config({"canary_endpoint": "tokenize", "correlation_s": 2, "pids": [4], "allow": ["10.0.0.1"]})[1] is None


def test_config_invalida_no_observa_nada():
    m = h6.H6Salidas()
    m.contexto = Contexto("linux", servidores=[servidor()])
    (h,) = m.ejecutar({"egress": {"desconocida": 1}})
    assert (h.id, h.severidad, h.estado) == ("H6-SALIDAS-CONFIG", Severidad.MEDIA, "sin_concluir")


# ------------------------------------------------------------------------------------------------ módulo
def modulo(s, so="linux", activos=False, explicito=False, procesos_=None, sockets=None, extra=()):
    m = h6.H6Salidas()
    m.contexto = Contexto(so, servidores=[s])
    m.activos_ok, m.pedido_explicito = activos, explicito
    m._leer_procesos = procesos_ or (lambda: {10: (1, "llama-server")})
    m._leer_sockets = sockets or (lambda pids: ([ESCUCHA], False))
    m._propias_extra = tuple(extra)
    return m


@pytest.fixture
def ventanas_cortas(monkeypatch):
    monkeypatch.setitem(h6.LIMITES, "active_window", (int, 30, 1, 1800))
    return {"passive_window": 1, "active_window": 2, "trailing": 1, "interval_ms": 50, "canaries": 3, "correlation_s": 0.9}


def test_sin_contexto():
    assert h6.H6Salidas().ejecutar({})[0].id == "H6-SALIDAS-SIN-CONTEXTO"


def test_en_all_solo_auditoria_estatica_sin_ventanas():
    llamadas = []
    m = modulo(servidor("llama.cpp", pid=10), sockets=lambda p: llamadas.append(p) or ([], False))
    ids = {h.id for h in m.ejecutar({})}
    assert llamadas == [] and {"H6-SALIDAS-CANARIO-OMITIDO", "H6-SALIDAS-RESUMEN"} <= ids
    assert "H6-SALIDAS-VENTANA-LIMPIA" not in ids


def test_host_no_local_no_observa(monkeypatch):
    monkeypatch.setattr(red, "es_host_local", lambda h: False)
    (h, *_) = modulo(servidor(pid=10)).ejecutar({})
    assert h.id == "H6-SALIDAS-NO-LOCAL" and h.estado == "sin_concluir"


def test_servidor_sin_pid_desde_windows_es_wsl():
    ids = [h.id for h in modulo(servidor("llama.cpp"), so="windows").ejecutar({})]
    assert "H6-SALIDAS-WSL" in ids and "H6-SALIDAS-RESUMEN" in ids
    assert "H6-SALIDAS-SIN-PID" in [h.id for h in modulo(servidor("llama.cpp"), so="linux").ejecutar({})]


def test_pedido_explicito_hace_la_ventana_pasiva_sin_a():
    m = modulo(servidor("llama.cpp", pid=10), explicito=True)
    hs = m.ejecutar({"egress": {"passive_window": 1, "interval_ms": 50}})
    ids = {h.id for h in hs}
    assert "H6-SALIDAS-VENTANA-LIMPIA" in ids and "H6-SALIDAS-CANARIO-OMITIDO" in ids
    limpia = next(h for h in hs if h.id == "H6-SALIDAS-VENTANA-LIMPIA")
    assert "No prueba que nunca salga nada" in limpia.evidencia and "50 ms" in limpia.evidencia


def test_ventana_pasiva_detecta_salida_alta():
    m = modulo(servidor("llama.cpp", pid=10), explicito=True,
               sockets=lambda p: ([ESCUCHA, fila(estado="SYN_SENT")], False))
    hs = m.ejecutar({"egress": {"passive_window": 1, "interval_ms": 100}})
    h = next(h for h in hs if h.id == "H6-SALIDAS-CONEXION-1")
    assert h.severidad == Severidad.ALTA and "SYN_SENT" in h.evidencia
    assert h.evidencia.startswith("llama.cpp en 127.0.0.1:8000")


def servidor_chat(extra_salidas, canarios, estado_chat=200):
    """Servidor falso con /health y chat; al recibir un canario añade una conexión saliente a la tabla simulada."""
    def responder(p):
        if p.metodo == "GET" and p.ruta in ("/health", "/v1/models"):
            return 200, {"Content-Type": "application/json"}, json.dumps({"data": [{"id": "m"}]}).encode()
        if p.metodo == "POST":
            canarios.append((p.cabeceras.get("x-request-id", ""), p.cuerpo.decode()))
            if extra_salidas is not None:
                extra_salidas.append(fila(puerto_local=50100 + len(extra_salidas), estado="SYN_SENT"))
            return estado_chat, {"Content-Type": "application/json"}, b"{}"
        return 404, {}, b""
    return ServidorFalso(responder)


def test_integracion_correlacion_con_servidor_falso(ventanas_cortas):
    salidas, canarios = [], []
    with servidor_chat(salidas, canarios) as falso:
        s = servidor("llama.cpp", pid=10, puerto=falso.puerto)
        m = modulo(s, activos=True, sockets=lambda p: ([ESCUCHA, *salidas], False))
        hs = m.ejecutar({"egress": ventanas_cortas})
        ids = {h.id: h for h in hs}
        assert ids["H6-SALIDAS-CORRELACION"].severidad == Severidad.CRITICA
        assert ids["H6-SALIDAS-CONEXION-1"].severidad == Severidad.ALTA
        resumen = ids["H6-SALIDAS-RESUMEN"]
        assert "3 canario(s) (3 OK)" in resumen.evidencia and "1 públicas" in resumen.evidencia
    assert len(canarios) == 3
    marca = canarios[0][0]
    assert marca.startswith("MRR-H6-") and all(c[0] == marca and marca in c[1] for c in canarios)
    # El canario nunca llega al informe.
    informe = Informe({"name": "t", "authorization": {"authorized_by": "x", "scope": "y", "date": "z"}})
    informe.anadir(hs)
    assert marca not in informe.to_json() and marca not in informe.to_markdown()


def test_integracion_ventana_limpia_con_servidor_falso(ventanas_cortas):
    canarios = []
    with servidor_chat(None, canarios) as falso:
        s = servidor("llama.cpp", pid=10, puerto=falso.puerto)
        hs = modulo(s, activos=True).ejecutar({"egress": ventanas_cortas})
    ids = {h.id for h in hs}
    assert "H6-SALIDAS-VENTANA-LIMPIA" in ids and "H6-SALIDAS-CORRELACION" not in ids and len(canarios) == 3


def test_canario_por_tokenize_en_vllm(ventanas_cortas):
    canarios, rutas = [], []

    def responder(p):
        rutas.append((p.metodo, p.ruta))
        if p.metodo == "GET":
            return 200, {}, json.dumps({"data": [{"id": "modelo-x"}]}).encode()
        canarios.append(json.loads(p.cuerpo))
        return 200, {}, b"{}"
    with ServidorFalso(responder) as falso:
        s = servidor("vllm", pid=10, puerto=falso.puerto)
        cfg = {**ventanas_cortas, "canary_endpoint": "tokenize", "canaries": 2, "active_window": 1}
        modulo(s, activos=True).ejecutar({"egress": cfg})
    assert ("POST", "/tokenize") in rutas and ("POST", "/v1/chat/completions") not in rutas
    assert canarios[0]["model"] == "modelo-x" and "MRR-H6-" in canarios[0]["prompt"]


def test_servidor_caido_tras_la_primera_peticion(ventanas_cortas, monkeypatch):
    llamadas = [0]

    def responde(url, clave, espera=5.0, dormir=None):
        llamadas[0] += 1
        return llamadas[0] == 1          # responde antes de enviar; deja de responder tras la primera petición
    monkeypatch.setattr(h6, "_responde", responde)
    with ServidorFalso(lambda p: (200, {}, b"{}")) as falso:
        s = servidor("llama.cpp", pid=10, puerto=falso.puerto)
        hs = modulo(s, activos=True).ejecutar({"egress": ventanas_cortas})
    assert "H6-SALIDAS-SERVIDOR-CAIDO" in {h.id for h in hs}


def test_servidor_que_no_responde_no_recibe_canario(ventanas_cortas, monkeypatch):
    monkeypatch.setattr(h6, "_responde", lambda *a, **k: False)
    hs = modulo(servidor("llama.cpp", pid=10), activos=True).ejecutar({"egress": ventanas_cortas})
    assert "H6-SALIDAS-CANARIO-SIN-RESPUESTA" in {h.id for h in hs}


def test_seccion_del_informe_y_frase_de_limites(ventanas_cortas):
    with servidor_chat(None, []) as falso:
        s = servidor("vllm", pid=10, puerto=falso.puerto, entorno={"VLLM_LOGGING_LEVEL": "INFO"})
        hs = modulo(s, activos=True).ejecutar({"egress": ventanas_cortas})
    informe = Informe({"name": "t", "authorization": {"authorized_by": "x", "scope": "y", "date": "z"}})
    informe.anadir(hs)
    md = informe.to_markdown()
    assert "## Salidas de datos a la red (H6)" in md and "| Canal | Estado |" in md and "TELEMETRIA" in md
    assert "No prueba que nunca salga nada" in md
    json.loads(informe.to_json())


def test_registro_en_el_cli():
    from mrrobotia import cli
    assert any(isinstance(m, h6.H6Salidas) for m in cli.MODULOS)
    assert nucleo.ALIAS_HITOS["H6"] == "Young_Elliot"


# ------------------------------------------------------------------------------------------------ sin proceso visible
def test_macos_con_pids_declarados_no_envia_canario(ventanas_cortas):
    canarios = []
    with servidor_chat(None, canarios) as falso:
        s = servidor("llama.cpp", puerto=falso.puerto)
        hs = modulo(s, so="macos", activos=True).ejecutar({"egress": {**ventanas_cortas, "pids": [10]}})
    ids = {h.id: h for h in hs}
    assert canarios == []
    assert ids["H6-SALIDAS-SO-NO-SOPORTADO"].estado == "sin_concluir" and "solo lee" in ids["H6-SALIDAS-SO-NO-SOPORTADO"].evidencia
    assert not {"H6-SALIDAS-VENTANA-LIMPIA", "H6-SALIDAS-CORRELACION", "H6-SALIDAS-CANARIO-OMITIDO"} & set(ids)
    cabecera = ids["H6-SALIDAS-RESUMEN"].evidencia
    assert "canales sin comprobar: DESCARGA, RPC, MCP, PROXY-UI, PROXY" in cabecera


def test_windows_sin_proceso_marca_los_canales_sin_comprobar():
    hs = {h.id: h for h in modulo(servidor("llama.cpp"), so="windows").ejecutar({})}
    tabla = {t["canal"]: t["estado"] for t in hs["H6-SALIDAS-RESUMEN"].detalle["canales"]}
    assert all(tabla[c] == "sin comprobar" for c in ("DESCARGA", "RPC", "MCP", "PROXY-UI", "PROXY"))
    assert tabla["TELEMETRIA"] == "cerrado"
    assert "sin comprobar" in hs["H6-SALIDAS-WSL"].evidencia and "no se ha observado" in hs["H6-SALIDAS-WSL"].evidencia
    assert "ninguno de los comprobados" in hs["H6-SALIDAS-RESUMEN"].evidencia
    _, tabla_vllm = canales(servidor("vllm"))
    assert {t["canal"] for t in tabla_vllm if t["estado"] == "sin comprobar"} >= {"HUB", "TRAZAS", "KV-EVENTOS", "MCP", "TELEMETRIA"}


def test_linux_con_proceso_visible_no_marca_sin_comprobar():
    s = servidor("llama.cpp", pid=10, opciones={"model": "m.gguf"})
    _, tabla = canales(s)
    assert not [t for t in tabla if t["estado"] == "sin comprobar"]
    hs = {h.id: h for h in modulo(s, explicito=True).ejecutar({"egress": {"passive_window": 1, "interval_ms": 50}})}
    assert "H6-SALIDAS-VENTANA-LIMPIA" in hs and "sin comprobar" not in hs["H6-SALIDAS-RESUMEN"].evidencia
    assert "canales abiertos: ninguno" in hs["H6-SALIDAS-RESUMEN"].evidencia


def test_pids_declarados_inexistentes_no_envian_canario(ventanas_cortas):
    canarios = []
    with servidor_chat(None, canarios) as falso:
        s = servidor("llama.cpp", puerto=falso.puerto)
        m = modulo(s, activos=True, procesos_=lambda: {10: (1, "otro")})
        hs = m.ejecutar({"egress": {**ventanas_cortas, "pids": [999], "process_names": ["no-existe"]}})
    ids = {h.id: h for h in hs}
    assert canarios == [] and ids["H6-SALIDAS-SIN-PID"].estado == "sin_concluir"
    assert "ningún canario" in ids["H6-SALIDAS-SIN-PID"].evidencia and "H6-SALIDAS-VENTANA-LIMPIA" not in ids


def test_pids_declarados_dicen_por_que_los_canales_salen_sin_comprobar():
    """Con egress.pids sí se observa, pero la línea de órdenes no se analiza: la fila no dice «no hay proceso»."""
    _, tabla = canales(servidor("llama.cpp"))
    filas = [t for t in tabla if t["estado"] == "sin comprobar"]
    assert filas and all("egress.pids" in t["evidencia"] and "no hay proceso" not in t["evidencia"] for t in filas)


def _arbol_que_muere(monkeypatch, antes_de):
    """El árbol (PID 10) existe hasta que empieza la ventana `antes_de` ("activa") o justo después de la pasiva."""
    vivo, real = [True], h6.observar

    def observar(*a, **k):
        if k.get("ventana") == antes_de:
            vivo[0] = False
        obs = real(*a, **k)
        if antes_de == "tras_pasiva" and k.get("ventana") == "pasiva":
            vivo[0] = False
        return obs
    monkeypatch.setattr(h6, "observar", observar)
    return lambda: {10: (1, "llama-server")} if vivo[0] else {20: (1, "otro")}


def test_si_el_arbol_desaparece_tras_la_pasiva_no_se_envia_canario(ventanas_cortas, monkeypatch):
    """Antes del arreglo, el árbol solo se comprobaba antes de la pasiva: el canario salía sin nadie observando."""
    canarios, procesos_ = [], _arbol_que_muere(monkeypatch, "tras_pasiva")
    with servidor_chat(None, canarios) as falso:
        s = servidor("llama.cpp", pid=10, puerto=falso.puerto, opciones={"model": "m.gguf"})
        hs = {h.id: h for h in modulo(s, activos=True, procesos_=procesos_).ejecutar({"egress": ventanas_cortas})}
    assert canarios == []
    assert "tras la ventana pasiva" in hs["H6-SALIDAS-SIN-PID"].titulo and "ningún canario" in hs["H6-SALIDAS-SIN-PID"].evidencia
    assert "H6-SALIDAS-VENTANA-LIMPIA" in hs                      # la pasiva sí se observó y estaba limpia
    assert "activa 0 s" in hs["H6-SALIDAS-RESUMEN"].evidencia


def test_una_ventana_sin_arbol_no_cuenta_como_limpia(ventanas_cortas, monkeypatch):
    """Antes del arreglo bastaba con ver el árbol en una ventana: VENTANA-LIMPIA sumaba también los segundos de la otra."""
    canarios, procesos_ = [], _arbol_que_muere(monkeypatch, "activa")
    with servidor_chat(None, canarios) as falso:
        s = servidor("llama.cpp", pid=10, puerto=falso.puerto, opciones={"model": "m.gguf"})
        hs = {h.id: h for h in modulo(s, activos=True, procesos_=procesos_).ejecutar({"egress": ventanas_cortas})}
    assert "ventana activa" in hs["H6-SALIDAS-SIN-PID"].evidencia
    segundos = float(re.search(r"durante ([\d.]+) s", hs["H6-SALIDAS-VENTANA-LIMPIA"].evidencia).group(1))
    assert segundos < ventanas_cortas["passive_window"] + 1        # solo la pasiva: la activa dura 3 s
    assert hs["H6-SALIDAS-RESUMEN"].detalle["limites"].startswith(f"Sin salidas del árbol del servidor durante {segundos:g} s")
