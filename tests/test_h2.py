"""Pruebas de H2: inventario y exposición del servidor LLM (llama.cpp).

Prueba las funciones PURAS con entradas fabricadas (sin levantar ningún servidor ni
llamar a herramientas externas) y un test de integración ligero de `ejecutar()` en
modo pasivo. Verifica además el invariante de privacidad: la evidencia nunca contiene
el texto de un prompt ni el VALOR de una variable de entorno.
"""
import os

from mrrobot.modulos import h2_exposicion as h2
from mrrobot.modulos.h2_exposicion import H2Exposicion
from mrrobot.nucleo import Severidad


# --------------------------------------------------------------- _bind_desde_tabla
def test_bind_desde_tabla_clasifica():
    win_todas = "  TCP    0.0.0.0:8080     0.0.0.0:0     LISTENING   1234"
    win_loop = "  TCP    127.0.0.1:8080   0.0.0.0:0     LISTENING   5678"
    lan = "  TCP    192.168.1.50:8080   0.0.0.0:0   LISTENING   4321"
    otro_puerto = "  TCP    127.0.0.1:9999   0.0.0.0:0   LISTENING   9"

    assert h2._bind_desde_tabla(win_todas, 8080) == "todas"
    assert h2._bind_desde_tabla(win_loop, 8080) == "loopback"
    assert h2._bind_desde_tabla("127.0.0.1:8080", 8080) == "loopback"     # cadena mínima
    assert h2._bind_desde_tabla(lan, 8080) == ("otra", "192.168.1.50")
    assert h2._bind_desde_tabla("192.168.1.50:8080", 8080) == ("otra", "192.168.1.50")
    assert h2._bind_desde_tabla(otro_puerto, 8080) is None                # puerto ausente
    assert h2._bind_desde_tabla("", 8080) is None


def test_bind_desde_tabla_ipv6_y_prioridad():
    # IPv6 loopback con corchetes (Windows) y sin ellos (netstat Linux) -> loopback.
    assert h2._bind_desde_tabla("  TCP  [::1]:8080  [::]:0  LISTENING  1", 8080) == "loopback"
    assert h2._bind_desde_tabla("tcp6 0 0 ::1:8080 :::* LISTEN 1/x", 8080) == "loopback"
    # ':::8080' es '::' (todas las interfaces IPv6).
    assert h2._bind_desde_tabla("tcp6 0 0 :::8080 :::* LISTEN 1/x", 8080) == "todas"
    # Si conviven loopback y todas, prevalece la exposición máxima.
    tabla = ("  TCP  127.0.0.1:8080  0.0.0.0:0  LISTENING  1\n"
             "  TCP  0.0.0.0:8080    0.0.0.0:0  LISTENING  1")
    assert h2._bind_desde_tabla(tabla, 8080) == "todas"


# ---------------------------------------------------------------- _pid_desde_tabla
def test_pid_desde_tabla():
    assert h2._pid_desde_tabla("  TCP    0.0.0.0:8080     0.0.0.0:0     LISTENING   1234", 8080) == 1234
    ss = 'LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:(("llama-server",pid=4321,fd=3))'
    assert h2._pid_desde_tabla(ss, 8080) == 4321
    assert h2._pid_desde_tabla("tcp 0 0 127.0.0.1:8080 0.0.0.0:* LISTEN 777/llama", 8080) == 777
    assert h2._pid_desde_tabla("no hay tabla aquí", 8080) is None


# --------------------------------------------------------------------- _evaluar_bind
def test_evaluar_bind():
    todas = h2._evaluar_bind("todas", "127.0.0.1", False)
    assert todas.id == "H2-BIND" and todas.severidad == Severidad.ALTA

    loop = h2._evaluar_bind("loopback", "127.0.0.1", False)
    assert loop.id == "H2-BIND" and loop.severidad == Severidad.INFO

    otra = h2._evaluar_bind(("otra", "10.0.0.5"), "127.0.0.1", False)
    assert otra.severidad == Severidad.ALTA

    # loopback cuando se esperaba otra cosa -> discrepancia MEDIA.
    mismatch = h2._evaluar_bind("loopback", "0.0.0.0", False)
    assert mismatch.severidad == Severidad.MEDIA


# --------------------------------------------------------------------- _evaluar_auth
def test_evaluar_auth():
    critico = h2._evaluar_auth(200, True, False)       # expuesto y sin proxy
    assert critico.id == "H2-AUTH" and critico.severidad == Severidad.CRITICA

    loopback = h2._evaluar_auth(200, False, False)     # abierto pero solo local
    assert loopback.severidad == Severidad.MEDIA

    con_proxy = h2._evaluar_auth(200, True, True)      # expuesto pero tras proxy
    assert con_proxy.severidad == Severidad.MEDIA

    exige = h2._evaluar_auth(403, False, False)
    assert exige.severidad == Severidad.INFO


# -------------------------------------------------------------------- _evaluar_slots
def test_evaluar_slots_no_vuelca_prompt():
    PROMPT_SECRETO = "informacion secreta del usuario"   # jamás debe salir en la evidencia
    hall = h2._evaluar_slots(200, 2, True, False)
    assert hall.id == "H2-SLOTS"
    assert hall.severidad == Severidad.ALTA               # no expuesto -> ALTA
    assert "2" in hall.evidencia                          # solo el recuento
    assert "prompt" in hall.evidencia.lower()             # 'prompt' aparece solo como aviso de presencia
    assert PROMPT_SECRETO not in hall.evidencia           # nunca el texto

    # Expuesto -> CRITICA.
    assert h2._evaluar_slots(200, 1, False, True).severidad == Severidad.CRITICA
    # /slots no accesible -> sin hallazgo.
    assert h2._evaluar_slots(501, 0, False, False) is None


# -------------------------------------------------------------------- _evaluar_props
def test_evaluar_props_build_vulnerable():
    salida = h2._evaluar_props(200, "/ruta/modelo.gguf", "b11500-abc", False,
                               builds_vulnerables=["b11500"])
    por_id = {x.id: x for x in salida}
    assert por_id["H2-PROPS"].severidad == Severidad.MEDIA          # no expuesto
    assert por_id["H2-BUILD"].severidad == Severidad.INFO
    assert por_id["H2-BUILD-VULN"].severidad == Severidad.ALTA
    # Build no declarada vulnerable -> no hay H2-BUILD-VULN.
    sin_vuln = {x.id for x in h2._evaluar_props(200, "/m.gguf", "b99999", True)}
    assert "H2-BUILD-VULN" not in sin_vuln
    # /props no accesible -> lista vacía.
    assert h2._evaluar_props(404, None, None, False) == []


# ------------------------------------------------------------------ _severidad_compuesta
def test_severidad_compuesta():
    critico = h2._severidad_compuesta("todas", True, False)
    assert critico.id == "H2-EXPOSICION" and critico.severidad == Severidad.CRITICA

    con_auth = h2._severidad_compuesta("todas", False, False)       # expuesto pero con api-key
    assert con_auth.severidad == Severidad.ALTA

    loop = h2._severidad_compuesta("loopback", False, False)
    assert loop.severidad <= Severidad.BAJA                         # INFO o BAJA


# --------------------------------------------------------------------- _evaluar_env
def test_evaluar_env():
    hall = h2._evaluar_env(["OPENAI_API_KEY", "HF_TOKEN"])
    assert hall.severidad == Severidad.MEDIA
    assert "OPENAI_API_KEY" in hall.evidencia and "HF_TOKEN" in hall.evidencia
    assert h2._evaluar_env([]).severidad == Severidad.INFO


# ----------------------------------------------------------------------- _ip_rutable
def test_ip_rutable_no_lanza():
    ip = H2Exposicion()._ip_rutable()
    assert ip is None or isinstance(ip, str)


# ----------------------------------------------------- integración ligera (pasivo)
def test_ejecutar_pasivo_sin_activos_no_hace_http():
    m = H2Exposicion()
    m.activos_ok = False
    objetivo = {"nombre": "prueba local", "host": "127.0.0.1",
                "autorizacion": {"confirmo_no_local": False},
                "exposicion": {"puerto": 8080}}
    hallazgos = m.ejecutar(objetivo)
    ids = {h.id for h in hallazgos}

    # Siempre: enlace (o desconocido) + env + owner + omisión del sondeo activo.
    assert "H2-ACTIVO-OMITIDO" in ids
    assert ("H2-BIND" in ids) or ("H2-BIND-DESCONOCIDO" in ids)
    assert "H2-ENV" in ids
    assert "H2-OWNER" in ids
    # No se intentó ningún sondeo activo por HTTP.
    assert ids.isdisjoint({"H2-PORT", "H2-AUTH", "H2-SLOTS", "H2-PROPS", "H2-METRICS",
                           "H2-MODELS", "H2-TLS", "H2-WEBUI", "H2-EXPOSICION"})


def test_ejecutar_env_no_vuelca_valor(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "valor-secreto-123")
    m = H2Exposicion()
    m.activos_ok = False
    hallazgos = m.ejecutar({"autorizacion": {}, "exposicion": {"puerto": 8080}})
    volcado = " ".join(f"{x.titulo} {x.evidencia} {x.recomendacion}" for x in hallazgos)
    assert "GROQ_API_KEY" in volcado           # el NOMBRE sí
    assert "valor-secreto-123" not in volcado  # el VALOR nunca
