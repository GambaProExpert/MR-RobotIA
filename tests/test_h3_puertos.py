"""Pruebas de H3-PUERTOS: puertos abiertos innecesarios o inseguros del host.

Prueba la función PURA `_evaluar_puertos` con entradas fabricadas (sin red real ni
herramientas externas) y un par de pruebas de integración ligera de `ejecutar()` en modo
pasivo (con la tabla de puertos y el propietario parcheados, sin tocar la red). Verifica
también el invariante de privacidad: la evidencia es puerto/bind/pid y nunca vuelca datos
ni banners del servicio.
"""
from mrrobotia.contexto import Contexto, ServidorDetectado
from mrrobotia.modulos import h3_puertos as h3
from mrrobotia.modulos.h3_puertos import H3Puertos, _evaluar_puertos, PELIGROSOS
from mrrobotia.nucleo import Severidad
from mrrobotia.perfiles import PERFILES


# --------------------------------------------------- casos obligatorios (función pura)
def test_peligroso_no_loopback_sube_nivel():
    # 445 (SMB) base ALTA + enlace en todas las interfaces -> sube a CRITICA.
    hallazgos = _evaluar_puertos([(445, "todas", 10)], set(), PELIGROSOS)
    assert len(hallazgos) == 1
    h = hallazgos[0]
    assert h.id == "H3-PUERTOS-445"
    assert h.severidad == Severidad.CRITICA
    assert h.estado == "confirmado"


def test_solo_esperado_en_loopback_da_ok():
    hallazgos = _evaluar_puertos([(8080, "loopback", 10)], {8080}, PELIGROSOS)
    ids = {h.id for h in hallazgos}
    assert "H3-PUERTOS-OK" in ids
    h = next(h for h in hallazgos if h.id == "H3-PUERTOS-OK")
    assert h.severidad == Severidad.INFO
    # No hay ningún hallazgo de peligro.
    assert not any(x.id.startswith("H3-PUERTOS-") and x.id[len("H3-PUERTOS-"):].isdigit()
                   for x in hallazgos)


def test_inesperado_no_loopback_es_baja():
    hallazgos = _evaluar_puertos([(9999, "todas", 10)], {8080}, PELIGROSOS)
    assert len(hallazgos) == 1
    h = hallazgos[0]
    assert h.id == "H3-PUERTOS-INESPERADO-9999"
    assert h.severidad == Severidad.BAJA


def test_peligroso_loopback_mantiene_base_y_evidencia_sin_banners():
    SERVICIO_BANNER = "Redis 7.2.0 — datos del usuario"   # jamás debe salir en la evidencia
    hallazgos = _evaluar_puertos([(6379, "loopback", 10)], set(), PELIGROSOS)
    assert len(hallazgos) == 1
    h = hallazgos[0]
    assert h.id == "H3-PUERTOS-6379"
    assert h.severidad == Severidad.CRITICA            # base CRITICA, en loopback no sube
    assert "loopback" in h.evidencia                   # el enlace
    assert "10" in h.evidencia                          # el pid
    assert SERVICIO_BANNER not in h.evidencia           # nunca datos/banners del servicio
    assert "banner" not in h.evidencia.lower()


# ------------------------------------------------------ casos extra (función pura)
def test_media_sube_a_alta_por_expuestos_lan():
    # 161 (SNMP) base MEDIA; aunque el bind sea loopback, el barrido lo marca alcanzable.
    hallazgos = _evaluar_puertos([(161, "loopback", 7)], set(), PELIGROSOS,
                                 expuestos_lan={161})
    assert hallazgos[0].severidad == Severidad.ALTA


def test_inesperado_loopback_es_info():
    hallazgos = _evaluar_puertos([(4444, "loopback", 7)], set(), PELIGROSOS)
    assert hallazgos[0].id == "H3-PUERTOS-INESPERADO-4444"
    assert hallazgos[0].severidad == Severidad.INFO


def test_pid_desconocido_se_representa_con_interrogante():
    hallazgos = _evaluar_puertos([(3306, "todas", None)], set(), PELIGROSOS)
    assert "pid ?" in hallazgos[0].evidencia


def test_esperado_no_loopback_no_genera_ni_ok_ni_peligro():
    # Puerto esperado pero en todas las interfaces: H3 no lo señala (lo cubre H2) y no hay OK.
    hallazgos = _evaluar_puertos([(8000, "todas", 9)], {8000}, PELIGROSOS)
    assert hallazgos == []


# ------------------------------------------------ integración ligera (modo pasivo)
TABLA = (
    "  TCP    127.0.0.1:8080    0.0.0.0:0    LISTENING    1000\n"
    "  TCP    0.0.0.0:6379      0.0.0.0:0    LISTENING    2000\n"
)


def test_ejecutar_pasivo_detecta_peligroso_y_omite_activo(monkeypatch):
    monkeypatch.setattr(h3, "tabla_puertos", lambda: TABLA)
    monkeypatch.setattr(h3, "owner_proceso", lambda pid: None)   # sin tocar tasklist/proc
    # Red: aseguramos que el barrido NO se ejecuta (activos_ok=False); si se llamara, falla.
    monkeypatch.setattr(h3, "sondear", lambda *a, **k: (_ for _ in ()).throw(AssertionError("sondear")))
    monkeypatch.setattr(h3, "ip_rutable", lambda: None)

    m = H3Puertos()
    m.activos_ok = False
    objetivo = {"host": "127.0.0.1", "endpoint": "http://127.0.0.1:8080/v1", "autorizacion": {}}
    hallazgos = m.ejecutar(objetivo)
    ids = {h.id for h in hallazgos}

    assert "H3-PUERTOS-6379" in ids                 # Redis en 0.0.0.0 -> peligroso
    assert "H3-PUERTOS-ACTIVO-OMITIDO" in ids        # sin --permitir-activos
    # 8080 es el puerto declarado -> no se señala; y como 6379 es peligroso, no hay OK.
    assert "H3-PUERTOS-INESPERADO-8080" not in ids and "H3-PUERTOS-OK" not in ids
    redis = next(h for h in hallazgos if h.id == "H3-PUERTOS-6379")
    assert redis.severidad == Severidad.CRITICA      # base CRITICA (0.0.0.0 no la sube más)


def test_ejecutar_sin_tabla_da_hallazgo_informativo(monkeypatch):
    monkeypatch.setattr(h3, "tabla_puertos", lambda: "")
    m = H3Puertos()
    m.activos_ok = False
    hallazgos = m.ejecutar({"host": "127.0.0.1", "autorizacion": {}})
    ids = {h.id for h in hallazgos}
    assert "H3-PUERTOS-SIN-TABLA" in ids
    assert "H3-PUERTOS-OK" not in ids                # sin tabla no se afirma que todo esté bien


def test_invariante_privacidad_ejecutar_no_vuelca_datos(monkeypatch):
    monkeypatch.setattr(h3, "tabla_puertos", lambda: TABLA)
    monkeypatch.setattr(h3, "owner_proceso", lambda pid: None)
    m = H3Puertos()
    m.activos_ok = False
    hallazgos = m.ejecutar({"host": "127.0.0.1", "autorizacion": {}})
    volcado = " ".join(f"{x.titulo} {x.evidencia} {x.recomendacion}" for x in hallazgos)
    # La evidencia solo contiene puerto/bind/pid y texto de recomendación; nada de banners.
    assert "banner" not in volcado.lower()
    # El nombre de usuario del proceso nunca se vuelca (owner solo se resume como privilegiado).
    assert "Usuario" not in volcado and "SYSTEM" not in volcado


# ------------------------------------------------ adaptado a lo identificado
LLAMA, VLLM = PERFILES
CONFIRMADO = {"confirmo_no_local": True}


def ids(hallazgos):
    return {h.id for h in hallazgos}


def contexto(*servidores):
    return Contexto("linux", servidores=[ServidorDetectado(tipo, "127.0.0.1", puerto) for tipo, puerto in servidores])


def ejecutar(monkeypatch, tabla, ctx=None, objetivo=None, activos=False):
    monkeypatch.setattr(h3, "tabla_puertos", lambda: tabla)
    monkeypatch.setattr(h3, "owner_proceso", lambda pid: None)
    m = H3Puertos()
    m.activos_ok = activos
    m.contexto = ctx
    return m.ejecutar(objetivo or {"host": "127.0.0.1", "autorizacion": {}})


def fila(direccion):
    return f"  TCP    {direccion}    0.0.0.0:0    LISTENING    1000\n"


def test_puerto_del_servidor_identificado_es_esperado(monkeypatch):
    h = ejecutar(monkeypatch, fila("127.0.0.1:9931"), contexto(("llama.cpp", 9931)))
    assert ids(h) >= {"H3-PUERTOS-OK"} and "H3-PUERTOS-INESPERADO-9931" not in ids(h)


def test_sin_identificar_ese_puerto_no_es_esperado(monkeypatch):
    assert "H3-PUERTOS-INESPERADO-9931" in ids(ejecutar(monkeypatch, fila("127.0.0.1:9931"), contexto()))


def test_no_se_deduce_el_servidor_por_el_puerto(monkeypatch):
    # 8000 y 8265 eran «de vLLM» por deducción; sin identificarlo no son esperados.
    h = ejecutar(monkeypatch, fila("127.0.0.1:8000") + fila("127.0.0.1:8265"))
    assert {"H3-PUERTOS-INESPERADO-8000", "H3-PUERTOS-INESPERADO-8265"} <= ids(h)


def test_puertos_declarados_y_de_contexto_se_suman(monkeypatch):
    objetivo = {"host": "127.0.0.1", "autorizacion": {}, "puertos": {"esperados": [7000, "7001"]}}
    h = ejecutar(monkeypatch, fila("127.0.0.1:7000") + fila("127.0.0.1:7001") + fila("127.0.0.1:18080"),
                 contexto(("llama.cpp", 18080)), objetivo)
    assert not [i for i in ids(h) if i.startswith("H3-PUERTOS-INESPERADO")]


def test_sin_contexto_funciona_con_lo_declarado(monkeypatch):
    objetivo = {"host": "127.0.0.1", "autorizacion": {}, "puertos": {"esperados": [7000]}}
    h = ejecutar(monkeypatch, fila("127.0.0.1:7000"), None, objetivo)
    assert "H3-PUERTOS-OK" in ids(h)


def test_tipo_sin_perfil_no_aporta_canales(monkeypatch):
    h = ejecutar(monkeypatch, fila("0.0.0.0:5557"), contexto(("otro:algo", 1)))
    assert "H3-PUERTOS-INESPERADO-5557" in ids(h)


def test_canal_interno_en_loopback_no_se_senala(monkeypatch):
    h = ejecutar(monkeypatch, fila("127.0.0.1:29500"), contexto(("vllm", 8000)))
    assert "H3-PUERTOS-OK" in ids(h) and not [i for i in ids(h) if "29500" in i]


def test_canal_interno_fuera_de_loopback_es_alta(monkeypatch):
    h = ejecutar(monkeypatch, fila("0.0.0.0:5557") + fila("10.0.0.5:29550"), contexto(("vllm", 8000)))
    for puerto in (5557, 29550):
        interno = next(x for x in h if x.id == f"H3-PUERTOS-INTERNO-{puerto}")
        assert interno.severidad == Severidad.ALTA and "autenticación" in interno.recomendacion


def test_rpc_de_llamacpp_es_canal_interno(monkeypatch):
    assert 50052 in LLAMA.puertos_internos
    assert "H3-PUERTOS-INTERNO-50052" in ids(ejecutar(monkeypatch, fila("0.0.0.0:50052"), contexto(("llama.cpp", 18080))))


def test_canal_de_otro_servidor_no_cuenta(monkeypatch):
    # 5557 es de vLLM: en un host con llama.cpp es, simplemente, un puerto inesperado.
    h = ejecutar(monkeypatch, fila("0.0.0.0:5557"), contexto(("llama.cpp", 18080)))
    assert "H3-PUERTOS-INESPERADO-5557" in ids(h) and "H3-PUERTOS-INTERNO-5557" not in ids(h)


def test_canal_interno_se_marca_expuesto_por_el_barrido(monkeypatch):
    sondeados = []
    monkeypatch.setattr(h3, "ip_rutable", lambda: "192.0.2.10")
    monkeypatch.setattr(h3, "es_host_local", lambda host: True)
    monkeypatch.setattr(h3, "sondear", lambda host, p, timeout=2: sondeados.append((host, p)) or p == 5600)
    h = ejecutar(monkeypatch, fila("127.0.0.1:5600"), contexto(("vllm", 8000)), activos=True)
    assert "H3-PUERTOS-INTERNO-5600" in ids(h)
    assert {p for _, p in sondeados} >= set(PELIGROSOS) | set(VLLM.puertos_internos) | {8000}
    assert {d for d, _ in sondeados} == {"192.0.2.10"}


def test_barrido_desde_el_propio_equipo_no_afirma_acceso_externo(monkeypatch):
    monkeypatch.setattr(h3, "ip_rutable", lambda: "192.0.2.10")
    monkeypatch.setattr(h3, "es_host_local", lambda host: True)
    monkeypatch.setattr(h3, "sondear", lambda host, p, timeout=2: p == 6379)
    redis = next(x for x in ejecutar(monkeypatch, "", activos=True) if x.id == "H3-PUERTOS-6379")
    assert "IP de red de este equipo" in redis.titulo and "desde la red" not in redis.titulo


# -------------------------------------------------- un host que no es este equipo
def test_host_no_local_no_lee_la_tabla_del_auditor(monkeypatch):
    monkeypatch.setattr(h3, "tabla_puertos", lambda: (_ for _ in ()).throw(AssertionError("tabla del auditor")))
    m = H3Puertos()
    h = m.ejecutar({"host": "192.0.2.1", "autorizacion": CONFIRMADO})
    assert ids(h) == {"H3-PUERTOS-NO-LOCAL", "H3-PUERTOS-ACTIVO-OMITIDO"}
    assert all(x.severidad == Severidad.INFO for x in h)
    assert "permitir-activos" in next(x for x in h if x.id == "H3-PUERTOS-ACTIVO-OMITIDO").evidencia


def test_host_no_local_sin_confirmar_no_sondea(monkeypatch):
    monkeypatch.setattr(h3, "sondear", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no debe conectar")))
    m = H3Puertos()
    m.activos_ok = True
    h = m.ejecutar({"host": "192.0.2.1", "autorizacion": {}})
    assert "confirmo_no_local" in next(x for x in h if x.id == "H3-PUERTOS-ACTIVO-OMITIDO").evidencia


def test_host_no_local_solo_barre_ese_host(monkeypatch):
    sondeados = []
    monkeypatch.setattr(h3, "tabla_puertos", lambda: (_ for _ in ()).throw(AssertionError("tabla del auditor")))
    monkeypatch.setattr(h3, "ip_rutable", lambda: "10.9.9.9")
    monkeypatch.setattr(h3, "sondear", lambda host, p, timeout=2: sondeados.append(host) or p in (445, 5557))
    m = H3Puertos()
    m.activos_ok = True
    m.contexto = Contexto("linux", servidores=[ServidorDetectado("vllm", "192.0.2.1", 8000)])
    h = m.ejecutar({"host": "192.0.2.1", "autorizacion": CONFIRMADO})
    assert set(sondeados) == {"192.0.2.1"}
    assert {"H3-PUERTOS-445", "H3-PUERTOS-INTERNO-5557"} <= ids(h)
    assert "equipo auditor" in next(x for x in h if x.id == "H3-PUERTOS-445").titulo


def test_objetivo_malformado_no_llega_al_llamador(monkeypatch):
    h = ejecutar(monkeypatch, fila("127.0.0.1:7000"), objetivo={"host": "127.0.0.1", "autorizacion": {}, "exposicion": ["x"]})
    assert "H3-PUERTOS-INESPERADO-7000" in ids(h)


def test_host_local_por_su_ip_de_red_lee_la_tabla(monkeypatch):
    monkeypatch.setattr(h3, "es_host_local", lambda host: host == "10.1.2.3")
    h = ejecutar(monkeypatch, fila("0.0.0.0:6379"), objetivo={"host": "10.1.2.3", "autorizacion": CONFIRMADO})
    assert "H3-PUERTOS-6379" in ids(h) and "H3-PUERTOS-NO-LOCAL" not in ids(h)
