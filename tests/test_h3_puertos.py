"""Pruebas de H3-PUERTOS: puertos abiertos innecesarios o inseguros del host.

Prueba la función PURA `_evaluar_puertos` con entradas fabricadas (sin red real ni
herramientas externas) y un par de pruebas de integración ligera de `ejecutar()` en modo
pasivo (con la tabla de puertos y el propietario parcheados, sin tocar la red). Verifica
también el invariante de privacidad: la evidencia es puerto/bind/pid y nunca vuelca datos
ni banners del servicio.
"""
from mrrobotia.modulos import h3_puertos as h3
from mrrobotia.modulos.h3_puertos import H3Puertos, _evaluar_puertos, PELIGROSOS
from mrrobotia.nucleo import Severidad


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
    objetivo = {"servidor": "llama.cpp", "host": "127.0.0.1", "autorizacion": {}}
    hallazgos = m.ejecutar(objetivo)
    ids = {h.id for h in hallazgos}

    assert "H3-PUERTOS-6379" in ids                 # Redis en 0.0.0.0 -> peligroso
    assert "H3-PUERTOS-ACTIVO-OMITIDO" in ids        # sin --permitir-activos
    # 8080 es el esperado -> no se señala; y como 6379 es peligroso, no hay OK.
    assert "H3-PUERTOS-OK" not in ids
    redis = next(h for h in hallazgos if h.id == "H3-PUERTOS-6379")
    assert redis.severidad == Severidad.CRITICA      # base CRITICA (0.0.0.0 no la sube más)


def test_ejecutar_sin_tabla_da_hallazgo_informativo(monkeypatch):
    monkeypatch.setattr(h3, "tabla_puertos", lambda: "")
    m = H3Puertos()
    m.activos_ok = False
    hallazgos = m.ejecutar({"servidor": "vllm", "host": "127.0.0.1", "autorizacion": {}})
    ids = {h.id for h in hallazgos}
    assert "H3-PUERTOS-SIN-TABLA" in ids
    assert "H3-PUERTOS-OK" not in ids                # sin tabla no se afirma que todo esté bien


def test_invariante_privacidad_ejecutar_no_vuelca_datos(monkeypatch):
    monkeypatch.setattr(h3, "tabla_puertos", lambda: TABLA)
    monkeypatch.setattr(h3, "owner_proceso", lambda pid: None)
    m = H3Puertos()
    m.activos_ok = False
    hallazgos = m.ejecutar({"servidor": "llama.cpp", "host": "127.0.0.1", "autorizacion": {}})
    volcado = " ".join(f"{x.titulo} {x.evidencia} {x.recomendacion}" for x in hallazgos)
    # La evidencia solo contiene puerto/bind/pid y texto de recomendación; nada de banners.
    assert "banner" not in volcado.lower()
    # El nombre de usuario del proceso nunca se vuelca (owner solo se resume como privilegiado).
    assert "Usuario" not in volcado and "SYSTEM" not in volcado
