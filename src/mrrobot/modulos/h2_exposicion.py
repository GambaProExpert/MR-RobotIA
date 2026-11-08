"""
H2 — Inventario y exposición del servidor LLM (llama.cpp / llama-server).

Módulo HÍBRIDO: siempre hace una parte PASIVA (inventario local que no toca el
servicio: enlace de red del puerto, variables de entorno con claves de proveedores
y propietario del proceso) y, solo si el sondeo activo está autorizado, una parte
ACTIVA que sondea el endpoint HTTP para detectar superficie expuesta (sin API key,
/slots, /props, /v1/models, /metrics, CORS reflejado, HTTP sin TLS, interfaz web).

Autogating: NO se marca `activo=True` (así el CLI lo ejecuta siempre), sino que lee
`self.activos_ok` —que el CLI pone a True con --permitir-activos + permitir_activos—
para decidir si corre la parte activa. Para endpoints no locales exige, además,
autorizacion.confirmo_no_local, igual que el núcleo.

INVARIANTE DE PRIVACIDAD: la evidencia de los hallazgos son SOLO tasas, recuentos,
nombres de ruta de configuración y nombres de variable. NUNCA se vuelca el texto de
un prompt (si /slots trae un campo `prompt` no vacío se señala su PRESENCIA, nunca su
contenido) ni el VALOR de una variable de entorno (solo su nombre).

Diseño GENERAL (no depende de ningún caso del TFG): solo biblioteca estándar
(socket, urllib, subprocess, os, re, json, ssl) y NUNCA shell=True.

Separación para testabilidad: las funciones de módulo (prefijo `_evaluar_*`,
`_bind_desde_tabla`, `_pid_desde_tabla`) son PURAS y se prueban sin servidor ni
herramientas; los métodos del objeto (`_tabla_puertos`, `_ip_rutable`, `_sondear`,
`_http`, `_owner_proceso`) son los que tocan red/SO.

Atacantes del modelo de amenazas: A5 (exposición del servicio en red) y A3 (interno
con acceso a disco / otros procesos locales). Marcos: OWASP LLM Top 10 2025 (LLM10
Consumo ilimitado/exposición, LLM02 fuga de información, LLM03 cadena de suministro),
MITRE ATLAS y NIST AI 600-1.
"""
from __future__ import annotations

import json
import os
import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from mrrobot.nucleo import Modulo, Hallazgo, Severidad

# --------------------------------------------------------------------- constantes
# Marcos por tipo de debilidad.
REFS_EXPO = {"owasp": "LLM10", "atlas": "AML.T0049", "nist": "2.9"}      # exposición del servicio
REFS_FUGA = {"owasp": "LLM02", "atlas": "AML.T0057", "nist": "2.4"}      # fuga de prompt/estado (slots/props)
REFS_SECRETOS = {"owasp": "LLM02", "atlas": "AML.T0025", "nist": "2.9"}  # secretos en el entorno
REFS_SUPPLY = {"owasp": "LLM03", "atlas": "AML.T0010", "nist": "2.12"}   # build/CVE (cadena de suministro)
REFS_MODELS = {"owasp": "LLM02", "atlas": "AML.T0025", "nist": "2.4"}    # enumeración/rutas de modelos

PUERTO_DEFECTO = 8080
LOOPBACK = {"127.0.0.1", "::1", "localhost"}
TODAS_IFACES = {"0.0.0.0", "::", "*"}
# Nombres (NUNCA valores) de claves de API de proveedores que no deberían estar en
# el entorno de un servidor LLM auto alojado.
PATRONES_CLAVE_PROVEEDOR = [
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN",
    "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "GOOGLE_API_KEY", "GEMINI_API_KEY",
    "COHERE_API_KEY", "AZURE_OPENAI_API_KEY", "GROQ_API_KEY", "MISTRAL_API_KEY",
]
# Rutas que el sondeo activo comprueba (documenta la superficie HTTP revisada).
RUTAS_SENSIBLES = ["/slots", "/props", "/metrics", "/v1/models"]
TIMEOUT = 2
MAX_CUERPO = 1_000_000          # tope de lectura del cuerpo HTTP (defensa de memoria)


# ----------------------------------------------------- funciones puras: enlace/PID
def _clasificar_direccion(host):
    """Clasifica la parte de dirección de 'dir:puerto': 'loopback' | 'todas' |
    ('otra', ip) | None (si queda vacía). Quita los corchetes IPv6."""
    h = str(host).strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if not h:
        return None
    if h in LOOPBACK:
        return "loopback"
    if h in TODAS_IFACES:
        return "todas"
    return ("otra", h)


def _clasificaciones(lineas, sufijo):
    """Primera 'dir:puerto' de cada línea (la dirección local va antes que la remota)."""
    clases = []
    for linea in lineas:
        for token in linea.split():
            if token.endswith(sufijo) and len(token) > len(sufijo):
                clase = _clasificar_direccion(token[:-len(sufijo)])
                if clase is not None:
                    clases.append(clase)
                break   # solo la dirección local de esta línea
    return clases


def _bind_desde_tabla(salida, puerto):
    """Clasifica el enlace del puerto a partir de la tabla de `netstat`/`ss`.

    Devuelve 'loopback' | 'todas' | ('otra', ip) | None (si el puerto no aparece).
    Prefiere las líneas en estado de escucha (LISTEN/LISTENING) para no confundir el
    enlace local con una conexión saliente a ese mismo puerto; si no hay ninguna (p.
    ej. una línea suelta), procesa todas. Prioriza la exposición máxima encontrada.
    """
    sufijo = ":" + str(puerto)
    lineas = (salida or "").splitlines()
    escucha = [ln for ln in lineas if "listen" in ln.lower()]
    clases = _clasificaciones(escucha, sufijo) or _clasificaciones(lineas, sufijo)
    if not clases:
        return None
    if any(c == "todas" for c in clases):
        return "todas"
    for c in clases:
        if isinstance(c, tuple):        # ('otra', ip)
            return c
    return "loopback"


def _pid_desde_tabla(salida, puerto):
    """PID del proceso en escucha en ese puerto, o None. Best-effort y multiplataforma
    (ss: `pid=NNN`; netstat Linux: `NNN/prog`; netstat Windows: el PID es el último
    token entero)."""
    sufijo = ":" + str(puerto)
    for linea in (salida or "").splitlines():
        if "listen" not in linea.lower():
            continue
        tokens = linea.split()
        if not any(t.endswith(sufijo) and len(t) > len(sufijo) for t in tokens):
            continue
        m = re.search(r"pid=(\d+)", linea)      # ss: users:(("prog",pid=1234,fd=3))
        if m:
            return int(m.group(1))
        ultimo = tokens[-1] if tokens else ""
        if "/" in ultimo:                       # netstat Linux: "1234/prog"
            cab = ultimo.split("/", 1)[0]
            if cab.isdigit():
                return int(cab)
        if ultimo.isdigit():                    # netstat Windows: PID al final
            return int(ultimo)
    return None


# ----------------------------------------------------- funciones puras: evaluación
def _es_no_loopback(clase_bind):
    """¿El enlace deja el servicio fuera de loopback (todas las interfaces u otra IP)?"""
    return clase_bind == "todas" or (isinstance(clase_bind, tuple) and clase_bind[0] == "otra")


def _evaluar_bind(clase_bind, bind_esperado, proxy):
    """Enlace de red del servidor: 'todas'/'otra' -> ALTA; loopback distinto del
    esperado -> MEDIA; loopback esperado -> INFO."""
    pista_proxy = "" if proxy else " (no se declaró proxy autenticador)"
    if clase_bind == "todas":
        return Hallazgo(
            "H2", "H2-BIND", "El servidor LLM escucha en todas las interfaces de red",
            Severidad.ALTA, "confirmado",
            "enlace a todas las interfaces (0.0.0.0/::)",
            "Enlaza llama-server solo a 127.0.0.1 (--host 127.0.0.1) o ponlo tras un proxy inverso "
            "con autenticación; en todas las interfaces queda accesible desde la red (A5)." + pista_proxy,
            REFS_EXPO)
    if isinstance(clase_bind, tuple) and clase_bind[0] == "otra":
        return Hallazgo(
            "H2", "H2-BIND", "El servidor LLM escucha en una interfaz no local",
            Severidad.ALTA, "confirmado",
            f"enlace a {clase_bind[1]} (no es loopback)",
            "Enlaza a 127.0.0.1 salvo que la exposición en esa interfaz sea deliberada y esté "
            "protegida (proxy con autenticación, cortafuegos) (A5)." + pista_proxy,
            REFS_EXPO)
    # loopback
    if bind_esperado not in LOOPBACK:
        return Hallazgo(
            "H2", "H2-BIND", "El enlace del servidor no coincide con el esperado",
            Severidad.MEDIA, "confirmado",
            f"enlace a loopback; bind_esperado declarado = {bind_esperado!r}",
            "Revisa el arranque de llama-server: el enlace real no coincide con el declarado en el objetivo.",
            REFS_EXPO)
    return Hallazgo(
        "H2", "H2-BIND", "El servidor LLM escucha solo en loopback",
        Severidad.INFO, "informativo",
        "enlace a loopback (127.0.0.1/::1)",
        "", REFS_EXPO)


def _evaluar_auth(status, expuesto, proxy):
    """Respuesta de /props sin cabecera Authorization: 200 -> abierto (CRITICA si
    expuesto y sin proxy, si no MEDIA); 401/403 -> exige api-key (INFO)."""
    if status == 200:
        sev = Severidad.CRITICA if (expuesto and not proxy) else Severidad.MEDIA
        return Hallazgo(
            "H2", "H2-AUTH", "El servidor responde sin exigir API key",
            sev, "confirmado",
            "respuesta 200 sin cabecera Authorization",
            "Arranca llama-server con --api-key y exige la cabecera Authorization, o ponlo tras un "
            "proxy que autentique; sin clave, cualquiera que alcance el puerto puede usar el modelo (A5).",
            REFS_EXPO)
    if status in (401, 403):
        return Hallazgo(
            "H2", "H2-AUTH", "El servidor exige API key",
            Severidad.INFO, "informativo",
            f"respuesta {status} sin cabecera Authorization",
            "", REFS_EXPO)
    return Hallazgo(
        "H2", "H2-AUTH", "No se pudo determinar si el servidor exige API key",
        Severidad.INFO, "informativo",
        f"respuesta {status if status is not None else 'sin respuesta'} al sondear /props sin clave",
        "Comprueba a mano si el endpoint exige autenticación.", REFS_EXPO)


def _evaluar_slots(status, n_slots, hay_prompt, expuesto):
    """/slots accesible (200): ALTA (CRITICA si expuesto). La evidencia es SOLO el
    recuento; si hay un campo `prompt` no vacío se señala su PRESENCIA, nunca su texto."""
    if status != 200:
        return None
    sev = Severidad.CRITICA if expuesto else Severidad.ALTA
    evid = f"/slots accesible, {n_slots} slots"
    if hay_prompt:
        evid += " (campo prompt presente)"
    return Hallazgo(
        "H2", "H2-SLOTS", "El endpoint /slots expone el estado de las conversaciones",
        sev, "confirmado", evid,
        "Arranca llama-server sin --slots (o restringe /slots tras autenticación): expone el estado "
        "por slot y, con guardado de prompts, su contenido. Fuga de información del usuario (A5/LLM02).",
        REFS_FUGA)


def _evaluar_props(status, model_path, build, expuesto, builds_vulnerables=()):
    """/props accesible (200): revela model_path (MEDIA; ALTA si expuesto). Además,
    SIEMPRE un INFO de trazabilidad con la build y, si esa build coincide con un rango
    declarado vulnerable, una ALTA de cadena de suministro."""
    hallazgos = []
    if status != 200:
        return hallazgos
    sev = Severidad.ALTA if expuesto else Severidad.MEDIA
    if model_path:
        hallazgos.append(Hallazgo(
            "H2", "H2-PROPS", "El endpoint /props revela la ruta del modelo cargado",
            sev, "confirmado",
            f"/props accesible; model_path = {model_path}",
            "Restringe /props o ponlo tras autenticación: revela la ruta en disco del modelo y los "
            "parámetros del servidor, útiles para perfilar el despliegue (LLM02).",
            REFS_FUGA))
    else:
        hallazgos.append(Hallazgo(
            "H2", "H2-PROPS", "El endpoint /props está accesible",
            sev, "confirmado",
            "/props accesible (sin ruta de modelo legible en la respuesta)",
            "Restringe /props o ponlo tras autenticación: expone los parámetros del servidor (LLM02).",
            REFS_FUGA))
    # Trazabilidad de la build (reproducibilidad del TFG), sin secretos.
    hallazgos.append(Hallazgo(
        "H2", "H2-BUILD", "Build de llama.cpp/llama-server detectada",
        Severidad.INFO, "informativo",
        f"build = {build or 'desconocida'}",
        "", REFS_SUPPLY))
    if build and _build_vulnerable(build, builds_vulnerables):
        hallazgos.append(Hallazgo(
            "H2", "H2-BUILD-VULN", "La build del servidor coincide con un rango declarado vulnerable",
            Severidad.ALTA, "confirmado",
            f"build = {build} (coincide con un rango vulnerable declarado)",
            "Actualiza llama.cpp/llama-server a una build sin la vulnerabilidad declarada y revisa el "
            "aviso de seguridad correspondiente (LLM03, cadena de suministro).",
            REFS_SUPPLY))
    return hallazgos


def _evaluar_models(status, ids, expuesto):
    """/v1/models accesible (200): si algún id parece una ruta de disco -> MEDIA
    (fuga de rutas); si son solo alias -> BAJA (enumeración)."""
    if status != 200 or not ids:
        return None
    if any(_parece_ruta(i) for i in ids):
        return Hallazgo(
            "H2", "H2-MODELS", "El endpoint /v1/models revela rutas de disco de los modelos",
            Severidad.MEDIA, "confirmado",
            f"{len(ids)} modelo(s); algún id es una ruta de disco",
            "Expón alias en lugar de rutas en /v1/models: la ruta en disco informa al atacante de la "
            "estructura del despliegue (LLM02).",
            REFS_MODELS)
    return Hallazgo(
        "H2", "H2-MODELS", "El endpoint /v1/models enumera los modelos servidos",
        Severidad.BAJA, "confirmado",
        f"{len(ids)} modelo(s) enumerables (ids tipo alias)",
        "Si no es necesario, restringe /v1/models; permite enumerar los modelos disponibles.",
        REFS_MODELS)


def _evaluar_metrics(status, expuesto):
    """/metrics (Prometheus) accesible (200): MEDIA si expuesto, BAJA en loopback."""
    if status != 200:
        return None
    sev = Severidad.MEDIA if expuesto else Severidad.BAJA
    return Hallazgo(
        "H2", "H2-METRICS", "El endpoint /metrics (Prometheus) está accesible",
        sev, "confirmado", "/metrics accesible",
        "Restringe /metrics o ponlo tras autenticación: expone métricas de uso (tokens, latencias, "
        "nº de peticiones) útiles para perfilar el servicio (A5).",
        REFS_EXPO)


def _evaluar_cors(acao, allow_cred, origin_probe):
    """Access-Control-Allow-Origin: reflejar el Origin de la petición -> MEDIA (riesgo
    de DNS rebinding); comodín '*' -> BAJA."""
    if acao and acao == origin_probe:
        extra = " con Access-Control-Allow-Credentials" if allow_cred else ""
        return Hallazgo(
            "H2", "H2-CORS", "El servidor refleja el Origin en CORS (riesgo de DNS rebinding)",
            Severidad.MEDIA, "confirmado",
            f"Access-Control-Allow-Origin refleja el Origin de la petición{extra}",
            "No reflejes el Origin: fija una lista blanca de orígenes. Reflejarlo permite que una web "
            "maliciosa (DNS rebinding) use el servidor desde el navegador de la víctima (A5).",
            REFS_EXPO)
    if acao == "*":
        return Hallazgo(
            "H2", "H2-CORS", "El servidor permite CORS desde cualquier origen (*)",
            Severidad.BAJA, "confirmado",
            "Access-Control-Allow-Origin: *",
            "Restringe los orígenes permitidos a los estrictamente necesarios (A5).",
            REFS_EXPO)
    return None


def _evaluar_tls(esquema, expuesto):
    """Esquema de transporte: 'http' sin TLS -> ALTA si expuesto, BAJA en loopback;
    'https' -> INFO."""
    if str(esquema).lower() == "https":
        return Hallazgo(
            "H2", "H2-TLS", "El servidor usa HTTPS",
            Severidad.INFO, "informativo", "esquema https", "", REFS_EXPO)
    sev = Severidad.ALTA if expuesto else Severidad.BAJA
    return Hallazgo(
        "H2", "H2-TLS", "El servidor sirve en HTTP sin TLS",
        sev, "confirmado", "esquema http (sin cifrado en tránsito)",
        "Sirve tras TLS (proxy inverso con HTTPS) si el servicio sale de loopback; en claro, el "
        "tráfico y la API key viajan sin cifrar (A5).",
        REFS_EXPO)


def _evaluar_webui(status, expuesto):
    """Interfaz web integrada en '/' (200 HTML): MEDIA si expuesto, BAJA en loopback."""
    if status != 200:
        return None
    sev = Severidad.MEDIA if expuesto else Severidad.BAJA
    return Hallazgo(
        "H2", "H2-WEBUI", "La interfaz web integrada de llama-server está accesible",
        sev, "confirmado", "respuesta 200 HTML en '/'",
        "Si no usas la interfaz web, arranca con --no-webui; expuesta en red ofrece una consola de "
        "chat sin autenticación contra el modelo (A5).",
        REFS_EXPO)


def _evaluar_env(nombres_presentes):
    """Claves de API de proveedores en el entorno. Evidencia = NOMBRES, nunca valores."""
    nombres = sorted(set(nombres_presentes or ()))
    if nombres:
        return Hallazgo(
            "H2", "H2-ENV", "Hay claves de API de proveedores en variables de entorno",
            Severidad.MEDIA, "confirmado",
            "variables presentes: " + ", ".join(nombres),
            "Un servidor LLM auto alojado no debería necesitar claves de proveedores externos en su "
            "entorno; si un módulo o la app filtran el entorno, se exponen. Retíralas del proceso o usa "
            "un gestor de secretos. (Se informa solo del nombre, nunca del valor.)",
            REFS_SECRETOS)
    return Hallazgo(
        "H2", "H2-ENV", "No hay claves de API de proveedores en el entorno",
        Severidad.INFO, "informativo",
        "ninguna de las variables vigiladas está presente",
        "", REFS_SECRETOS)


def _severidad_compuesta(clase_bind, auth_abierta, proxy):
    """Resumen de exposición del servicio. No loopback + sin auth + sin proxy ->
    CRITICA; no loopback con auth o proxy -> ALTA; loopback -> BAJA/INFO."""
    if _es_no_loopback(clase_bind):
        if auth_abierta and not proxy:
            return Hallazgo(
                "H2", "H2-EXPOSICION", "Servidor LLM expuesto en red y sin autenticación",
                Severidad.CRITICA, "confirmado",
                "enlace no loopback + responde sin API key + sin proxy autenticador",
                "Enlaza a 127.0.0.1 y exige API key (--api-key) o pon un proxy con autenticación. Tal "
                "cual, cualquiera en la red puede usar el modelo sin credenciales (A5).",
                REFS_EXPO)
        matices = []
        if not auth_abierta:
            matices.append("con API key")
        if proxy:
            matices.append("tras proxy")
        detalle = "enlace no loopback" + (" (" + ", ".join(matices) + ")" if matices else "")
        return Hallazgo(
            "H2", "H2-EXPOSICION", "Servidor LLM accesible desde la red",
            Severidad.ALTA, "confirmado", detalle,
            "Confirma que la exposición en red es deliberada y que la autenticación (API key o proxy) es "
            "robusta; prefiere 127.0.0.1 si no necesitas acceso remoto (A5).",
            REFS_EXPO)
    # loopback (o enlace desconocido, tratado como no expuesto)
    if auth_abierta:
        return Hallazgo(
            "H2", "H2-EXPOSICION", "Servidor LLM en loopback sin API key",
            Severidad.BAJA, "confirmado",
            "enlace a loopback; responde sin API key (accesible solo localmente)",
            "Aun en loopback, considera exigir API key para limitar el acceso de otros procesos "
            "locales al modelo (A3).",
            REFS_EXPO)
    return Hallazgo(
        "H2", "H2-EXPOSICION", "Servidor LLM en loopback",
        Severidad.INFO, "informativo",
        "enlace a loopback; exige API key o no responde abierto",
        "", REFS_EXPO)


# ----------------------------------------------------- funciones puras: auxiliares
def _parece_ruta(idm):
    """¿El id de modelo parece una ruta absoluta de disco?"""
    s = str(idm)
    return "/" in s or "\\" in s or ":" in s


def _build_vulnerable(build, builds_vulnerables):
    """¿La build coincide con algún identificador de la lista declarada como vulnerable?
    Coincidencia por igualdad o por aparición del identificador declarado dentro de la
    build (p. ej. 'b11500' declarado dentro de 'b11500-...')."""
    b = str(build).strip()
    for v in builds_vulnerables or ():
        v = str(v).strip()
        if v and (v == b or v in b):
            return True
    return False


# ------------------------------------------------------------------------- módulo
class H2Exposicion(Modulo):
    nombre = "H2"
    titulo = "Inventario y exposición del servidor LLM (llama.cpp)"
    activo = False      # HÍBRIDO: se ejecuta siempre y autogatea las partes activas con self.activos_ok
    etiqueta_escaneo = "exposicion"

    # Constantes accesibles también como atributos del objeto (los métodos usan self.X).
    TIMEOUT = TIMEOUT
    MAX_CUERPO = MAX_CUERPO
    PUERTO_DEFECTO = PUERTO_DEFECTO
    LOOPBACK = LOOPBACK
    PATRONES_CLAVE_PROVEEDOR = PATRONES_CLAVE_PROVEEDOR
    RUTAS_SENSIBLES = RUTAS_SENSIBLES

    # ----------------------------------------------------------- recogida (red/SO)
    def _tabla_puertos(self):
        """Tabla de puertos en escucha (`netstat -ano` en Windows; `ss`/`netstat` en
        Linux). Nunca lanza ni usa shell: si todo falla, devuelve ''."""
        if os.name == "nt":
            ordenes = [["netstat", "-ano"]]
        else:
            ordenes = [["ss", "-ltnp"], ["netstat", "-ltnp"], ["ss", "-ltn"], ["netstat", "-ltn"]]
        for orden in ordenes:
            try:
                proc = subprocess.run(orden, capture_output=True, text=True, timeout=10)
            except (OSError, subprocess.SubprocessError):
                continue
            salida = (proc.stdout or "") + "\n" + (proc.stderr or "")
            if proc.returncode == 0 and salida.strip():
                return salida
        return ""

    def _ip_rutable(self):
        """IP local con la que el SO saldría a la red, sin enviar ningún paquete (se
        conecta un socket UDP a una IP de documentación). Devuelve la IP o None."""
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("192.0.2.1", 9))
            return s.getsockname()[0]
        except OSError:
            return None
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass

    def _sondear(self, host, port):
        """¿Hay algo escuchando en host:port? connect_ex con timeout; True/False."""
        fam = socket.AF_INET6 if ":" in str(host) else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(self.TIMEOUT)
        try:
            return s.connect_ex((host, int(port))) == 0
        except OSError:
            return False
        finally:
            try:
                s.close()
            except OSError:
                pass

    def _contexto_tls(self):
        """Contexto TLS que NO verifica el certificado: auditamos el servidor del
        propio usuario (a menudo con cert autofirmado), no confiamos en él."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _http(self, url, origin=None):
        """GET con timeout. Devuelve (status, cabeceras_min, cuerpo). Captura HTTPError
        (usa su código y cuerpo) y URLError (status None). NUNCA propaga."""
        cabeceras = {"Accept": "*/*"}
        if origin:
            cabeceras["Origin"] = origin
        req = urllib.request.Request(url, headers=cabeceras, method="GET")
        ctx = self._contexto_tls() if url.lower().startswith("https") else None
        try:
            with urllib.request.urlopen(req, timeout=self.TIMEOUT, context=ctx) as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                cuerpo = resp.read(self.MAX_CUERPO).decode("utf-8", "replace")
                return status, _cabeceras_min(resp.headers), cuerpo
        except urllib.error.HTTPError as e:
            try:
                cuerpo = e.read(self.MAX_CUERPO).decode("utf-8", "replace")
            except Exception:
                cuerpo = ""
            return e.code, _cabeceras_min(getattr(e, "headers", None)), cuerpo
        except (urllib.error.URLError, OSError, ValueError):
            return None, {}, ""

    def _owner_proceso(self, pid):
        """Usuario del proceso (best-effort): (es_privilegiado, etiqueta) o None si no
        se puede verificar. Linux lee /proc/<pid>/status (Uid); Windows usa tasklist."""
        if pid is None:
            return None
        try:
            if os.name != "nt":
                try:
                    with open(f"/proc/{int(pid)}/status", "r", encoding="utf-8", errors="replace") as f:
                        texto = f.read()
                except OSError:
                    return None
                for linea in texto.splitlines():
                    if linea.startswith("Uid:"):
                        partes = linea.split()
                        if len(partes) >= 2 and partes[1].isdigit():
                            uid = int(partes[1])
                            return (uid == 0, "root" if uid == 0 else f"uid {uid}")
                return None
            # Windows: tasklist /V da la columna "User Name" (índice 6 del CSV sin cabecera).
            proc = subprocess.run(
                ["tasklist", "/FI", f"PID eq {int(pid)}", "/V", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=self.TIMEOUT + 8)
            campos = re.findall(r'"([^"]*)"', proc.stdout or "")
            usuario = campos[6] if len(campos) >= 7 else None
            if not usuario or usuario.upper() == "N/A":
                return None
            bajo = usuario.lower()
            privilegiado = any(m in bajo for m in ("system", "administrator", "administrador"))
            return (privilegiado, usuario)
        except (OSError, subprocess.SubprocessError, ValueError):
            return None

    # ----------------------------------------------------------- parseo de cuerpos
    def _parsear_slots(self, status, body):
        """(n_slots, hay_prompt) de /slots. NUNCA devuelve el texto del prompt: solo si
        hay un campo `prompt` no vacío."""
        if status != 200 or not body:
            return 0, False
        try:
            datos = json.loads(body)
        except (ValueError, TypeError):
            return 0, False
        if isinstance(datos, list):
            slots = datos
        elif isinstance(datos, dict) and isinstance(datos.get("slots"), list):
            slots = datos["slots"]
        else:
            return 0, False
        hay_prompt = False
        for s in slots:
            if isinstance(s, dict):
                p = s.get("prompt")
                if (isinstance(p, str) and p.strip()) or (p not in (None, "", [], {})):
                    hay_prompt = True
                    break
        return len(slots), hay_prompt

    def _parsear_props(self, status, body):
        """(model_path, build) de /props. model_path/ruta en disco (no es secreto) y la
        build para trazabilidad."""
        if status != 200 or not body:
            return None, None
        try:
            datos = json.loads(body)
        except (ValueError, TypeError):
            return None, None
        if not isinstance(datos, dict):
            return None, None
        model_path = None
        for clave in ("model_path", "model"):
            v = datos.get(clave)
            if isinstance(v, str) and v.strip():
                model_path = v.strip()
                break
        if model_path is None:
            dgs = datos.get("default_generation_settings")
            if isinstance(dgs, dict) and isinstance(dgs.get("model"), str) and dgs["model"].strip():
                model_path = dgs["model"].strip()
        build = None
        bi = datos.get("build_info")
        if isinstance(bi, str) and bi.strip():
            build = bi.strip()
        elif isinstance(bi, dict):
            for clave in ("build", "number", "commit"):
                if bi.get(clave):
                    build = str(bi[clave])
                    break
        if build is None:
            for clave in ("build_number", "build_commit"):
                if datos.get(clave):
                    build = str(datos[clave])
                    break
        return model_path, build

    def _parsear_models(self, status, body):
        """Lista de ids de /v1/models (o [])."""
        if status != 200 or not body:
            return []
        try:
            datos = json.loads(body)
        except (ValueError, TypeError):
            return []
        lista = datos.get("data") if isinstance(datos, dict) else datos
        if not isinstance(lista, list):
            return []
        ids = []
        for d in lista:
            if isinstance(d, dict) and isinstance(d.get("id"), str) and d["id"]:
                ids.append(d["id"])
            elif isinstance(d, str) and d:
                ids.append(d)
        return ids

    # -------------------------------------------------------- construcción owner
    def _hallazgo_owner(self, pid):
        info = self._owner_proceso(pid)
        if info is None:
            ref = f" (pid {pid})" if pid is not None else " (pid desconocido)"
            return Hallazgo(
                "H2", "H2-OWNER", "No se pudo verificar el usuario del proceso del servidor",
                Severidad.INFO, "informativo",
                "propietario del proceso no verificable" + ref,
                "Comprueba a mano que el servidor no se ejecuta como root/SYSTEM; usa una cuenta sin "
                "privilegios (A3).", REFS_EXPO)
        privilegiado, etiqueta = info
        if privilegiado:
            return Hallazgo(
                "H2", "H2-OWNER", "El servidor LLM se ejecuta con una cuenta privilegiada",
                Severidad.ALTA, "confirmado",
                f"proceso (pid {pid}) ejecutado como {etiqueta}",
                "Ejecuta llama-server con una cuenta sin privilegios: si el servicio se ve comprometido, "
                "limita el impacto. No lo corras como root/SYSTEM (A3).", REFS_EXPO)
        return Hallazgo(
            "H2", "H2-OWNER", "El servidor LLM se ejecuta con una cuenta sin privilegios",
            Severidad.INFO, "informativo",
            f"proceso (pid {pid}) ejecutado como {etiqueta}",
            "", REFS_EXPO)

    # --------------------------------------------------------------- orquestación
    def ejecutar(self, objetivo):
        cfg = objetivo.get("exposicion", {}) or {}
        endpoint = objetivo.get("endpoint")
        if endpoint:
            p = urllib.parse.urlparse(endpoint)
            esquema = (p.scheme or "http").lower()
            host = p.hostname or objetivo.get("host") or cfg.get("host") or "127.0.0.1"
            puerto = p.port or cfg.get("puerto") or self.PUERTO_DEFECTO
        else:
            esquema = "http"
            host = objetivo.get("host") or cfg.get("host") or "127.0.0.1"
            puerto = cfg.get("puerto") or self.PUERTO_DEFECTO
        try:
            puerto = int(puerto)
        except (TypeError, ValueError):
            puerto = self.PUERTO_DEFECTO
        host_sondeo = host
        bind_esperado = cfg.get("bind_esperado", "127.0.0.1")
        proxy = bool(cfg.get("proxy_autenticador", False))
        # api_key_esperada: el objetivo declara si se espera clave; _evaluar_auth ya
        # marca cualquier 200 abierto, así que se lee para dejarlo explícito/trazable.
        api_key_esperada = bool(cfg.get("api_key_esperada", True))
        builds_vulnerables = cfg.get("builds_vulnerables") or []

        hallazgos = []

        # ---- PASIVAS (siempre) -------------------------------------------------
        tabla = self._tabla_puertos()
        clase_bind = _bind_desde_tabla(tabla, puerto)
        pid = _pid_desde_tabla(tabla, puerto)
        if clase_bind is None:
            hallazgos.append(Hallazgo(
                "H2", "H2-BIND-DESCONOCIDO", "No se pudo determinar el enlace de red del servidor",
                Severidad.INFO, "informativo",
                f"sin entrada para el puerto {puerto} en la tabla de puertos (o tabla no disponible)",
                "Comprueba a mano con 'netstat -ano' (Windows) o 'ss -ltnp' (Linux) a qué interfaz "
                "enlaza el servidor.", REFS_EXPO))
        else:
            hallazgos.append(_evaluar_bind(clase_bind, bind_esperado, proxy))

        nombres_env = [n for n in self.PATRONES_CLAVE_PROVEEDOR if n in os.environ]
        hallazgos.append(_evaluar_env(nombres_env))

        hallazgos.append(self._hallazgo_owner(pid))

        expuesto_bind = _es_no_loopback(clase_bind)

        # ---- GATING ACTIVO -----------------------------------------------------
        activos = getattr(self, "activos_ok", False)
        no_local = host_sondeo not in self.LOOPBACK
        if no_local and objetivo.get("autorizacion", {}).get("confirmo_no_local") is not True:
            hallazgos.append(Hallazgo(
                "H2", "H2-ACTIVO-OMITIDO", "Sondeo activo de H2 omitido",
                Severidad.INFO, "informativo",
                "endpoint no local sin confirmo_no_local",
                "Marca autorizacion.confirmo_no_local=true solo con permiso escrito para sondear un "
                "host no local.", REFS_EXPO))
            return [h for h in hallazgos if h is not None]
        if not activos:
            hallazgos.append(Hallazgo(
                "H2", "H2-ACTIVO-OMITIDO", "Sondeo activo de H2 omitido",
                Severidad.INFO, "informativo",
                "sondeo activo omitido: requiere --permitir-activos y permitir_activos=true",
                "Habilita --permitir-activos y permitir_activos=true en el objetivo para el sondeo "
                "activo de exposición.", REFS_EXPO))
            return [h for h in hallazgos if h is not None]

        # ---- ACTIVAS (solo si autorizado y host permitido) ---------------------
        try:
            self._sondear_activo(hallazgos, esquema, host_sondeo, puerto, proxy,
                                 api_key_esperada, expuesto_bind, clase_bind, builds_vulnerables)
        except Exception as e:
            hallazgos.append(Hallazgo(
                "H2", "H2-ERROR", "Error durante el sondeo activo de exposición",
                Severidad.INFO, "informativo", type(e).__name__,
                "Revisa la configuración de 'exposicion' en el objetivo y el estado del servidor.",
                REFS_EXPO))

        return [h for h in hallazgos if h is not None]

    def _sondear_activo(self, h, esquema, host, puerto, proxy, api_key_esperada,
                        expuesto_bind, clase_bind, builds_vulnerables):
        """Parte activa: acumula hallazgos en `h` (para conservar los parciales si algo
        falla). Si el puerto está cerrado, no hay nada que sondear por HTTP."""
        abierto = self._sondear(host, puerto)
        h.append(Hallazgo(
            "H2", "H2-PORT", "Puerto del servidor " + ("abierto" if abierto else "cerrado"),
            Severidad.INFO, "informativo",
            f"{host}:{puerto} {'abierto' if abierto else 'cerrado'}",
            "" if abierto else "El servidor no responde en ese puerto; arráncalo o revisa host/puerto.",
            REFS_EXPO))
        if not abierto:
            return

        # ¿Accesible desde una IP rutable (no loopback)?
        expuesto_lan = False
        ip = self._ip_rutable()
        if ip and ip not in self.LOOPBACK and self._sondear(ip, puerto):
            expuesto_lan = True
            h.append(Hallazgo(
                "H2", "H2-LAN", "El servidor responde en una IP de red (accesible desde la LAN)",
                Severidad.ALTA, "confirmado",
                f"responde en {ip}:{puerto} (IP rutable, no loopback)",
                "Enlaza a 127.0.0.1 o protege el acceso desde la red (cortafuegos, proxy con "
                "autenticación) (A5).", REFS_EXPO))
        expuesto = expuesto_bind or expuesto_lan

        base = f"{esquema}://{host}:{puerto}"

        # Auth: /props sin Authorization.
        st_props, _, body_props = self._http(base + "/props")
        h.append(_evaluar_auth(st_props, expuesto, proxy))
        auth_abierta = (st_props == 200)

        # /slots (estado de conversaciones; nunca se vuelca el texto del prompt).
        st_slots, _, body_slots = self._http(base + "/slots")
        n_slots, hay_prompt = self._parsear_slots(st_slots, body_slots)
        h.append(_evaluar_slots(st_slots, n_slots, hay_prompt, expuesto))

        # /props (reutiliza la respuesta de auth): ruta del modelo + build.
        model_path, build = self._parsear_props(st_props, body_props)
        h.extend(_evaluar_props(st_props, model_path, build, expuesto, builds_vulnerables))

        # /v1/models
        st_models, _, body_models = self._http(base + "/v1/models")
        ids = self._parsear_models(st_models, body_models)
        h.append(_evaluar_models(st_models, ids, expuesto))

        # /metrics
        st_metrics, _, _ = self._http(base + "/metrics")
        h.append(_evaluar_metrics(st_metrics, expuesto))

        # CORS (sonda con un Origin inventado sobre /health).
        origin_probe = "http://mrrobot.invalid"
        _, hd_health, _ = self._http(base + "/health", origin=origin_probe)
        acao = hd_health.get("access-control-allow-origin")
        allow_cred = str(hd_health.get("access-control-allow-credentials", "")).lower() == "true"
        h.append(_evaluar_cors(acao, allow_cred, origin_probe))

        # TLS
        h.append(_evaluar_tls(esquema, expuesto))

        # Interfaz web en '/'
        st_root, hd_root, body_root = self._http(base + "/")
        es_html = ("text/html" in str(hd_root.get("content-type", "")).lower()
                   or "<html" in (body_root or "").lower())
        h.append(_evaluar_webui(st_root if es_html else None, expuesto))

        # Severidad compuesta de exposición.
        h.append(_severidad_compuesta(clase_bind if clase_bind is not None else "loopback",
                                      auth_abierta, proxy))


# --------------------------------------------------------------------- auxiliar HTTP
def _cabeceras_min(msg):
    """Cabeceras HTTP a un dict con claves en minúsculas (lectura insensible a mayúsculas)."""
    out = {}
    if msg is None:
        return out
    try:
        for k, v in msg.items():
            out[str(k).lower()] = v
    except Exception:
        pass
    return out
