"""
Utilidades de red y de sistema compartidas por los módulos que inventarían puertos y
enlaces de red (H2 — identificación y exposición del endpoint; H3-PUERTOS — puertos del
host), y cliente HTTP de sondeo (`ClienteHTTP`).

Solo biblioteca estándar. Las funciones que ejecutan procesos usan SIEMPRE una lista de
argumentos y NUNCA `shell=True` (evita inyección por la shell del host). Ninguna función
lanza al llamador: ante un fallo devuelven un valor neutro (None/""/False).
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import time
import urllib.parse
import zlib
from dataclasses import dataclass

LOOPBACK = {"127.0.0.1", "::1", "localhost"}
TODAS_IFACES = {"0.0.0.0", "::", "*"}
TIMEOUT_SONDEO = 2          # s de espera al sondear un puerto
TIMEOUT_PROCESO = 10        # s de espera a netstat/ss/tasklist

# En Windows, netstat atribuye a estos PID las filas que no sabe asignar (TIME_WAIT o el
# propio núcleo): no identifican al proceso que escucha y se tratan como desconocidos.
PIDS_DESCONOCIDOS = {0, 4}
# Dirección remota de un socket TCP en escucha, diga lo que diga su columna de estado.
REMOTAS_DE_ESCUCHA = {"0.0.0.0:0", "[::]:0", "*:*"}

MAX_CUERPO = 1_000_000          # tope de lectura del cuerpo HTTP (defensa de memoria)
MAX_DESCOMPRIMIDO = 4_000_000   # tope tras descomprimir gzip (defensa frente a bombas)
AGENTE = "MRRobotIA"


# ------------------------------------------------- funciones puras: enlace/PID
def decodificar(datos):
    """Bytes de una orden del sistema a texto, sin lanzar nunca: UTF-8 si lo es y, si no,
    la página OEM de la consola de Windows (netstat y tasklist en español no son UTF-8)."""
    if not datos:
        return ""
    try:
        return datos.decode("utf-8")
    except UnicodeDecodeError:
        return datos.decode("oem" if os.name == "nt" else "utf-8", "replace")


def a_puerto(valor):
    """Entero de puerto válido (1-65535) o None."""
    try:
        puerto = int(str(valor).strip())
    except (TypeError, ValueError):
        return None
    return puerto if 0 < puerto <= 65535 else None


def _es_ip_loopback(texto):
    """¿Es una IP del rango de loopback (127.0.0.0/8, ::1 o su forma IPv4 mapeada)?"""
    try:
        ip = ipaddress.ip_address(texto)
    except ValueError:
        return False
    return (getattr(ip, "ipv4_mapped", None) or ip).is_loopback


def clasificar_direccion(host):
    """Clasifica la parte de dirección de 'dir:puerto': 'loopback' | 'todas' |
    ('otra', ip) | None (si queda vacía). Quita los corchetes IPv6 y la zona de `ss`
    (`127.0.0.53%lo`)."""
    h = str(host).strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if not h:
        return None
    sin_zona = h.split("%", 1)[0]
    if sin_zona in LOOPBACK or _es_ip_loopback(sin_zona):
        return "loopback"
    if h in TODAS_IFACES:
        return "todas"
    return ("otra", h)


def es_fila_escucha(linea):
    """¿Es una fila de socket en escucha de la tabla de `netstat`/`ss`?

    No basta con buscar LISTEN: Windows traduce el estado según el idioma y en algunos
    equipos lo da incoherente (`0.0.0.0:1236  0.0.0.0:0  FIN_WAIT_1`). Por eso también
    cuenta una fila TCP cuya dirección remota es la de un socket sin conexión. Las filas
    UDP tienen remota `*:*` y no escuchan en el sentido de TCP.
    """
    if "listen" in linea.lower():
        return True
    tokens = linea.split()
    return (len(tokens) >= 3 and tokens[0].lower().startswith("tcp")
            and tokens[2] in REMOTAS_DE_ESCUCHA)


def clasificaciones(lineas, sufijo):
    """Primera 'dir:puerto' de cada línea (la dirección local va antes que la remota)."""
    clases = []
    for linea in lineas:
        for token in linea.split():
            if token.endswith(sufijo) and len(token) > len(sufijo):
                clase = clasificar_direccion(token[:-len(sufijo)])
                if clase is not None:
                    clases.append(clase)
                break   # solo la dirección local de esta línea
    return clases


def bind_desde_tabla(salida, puerto):
    """Clasifica el enlace del puerto a partir de la tabla de `netstat`/`ss`.

    Devuelve 'loopback' | 'todas' | ('otra', ip) | None (si no hay fila en escucha para
    ese puerto). Solo mira filas en escucha: una conexión establecida o en TIME_WAIT no
    dice a qué interfaz está enlazado el servidor. Prioriza la exposición máxima.
    """
    sufijo = ":" + str(puerto)
    escucha = [ln for ln in (salida or "").splitlines() if es_fila_escucha(ln)]
    clases = clasificaciones(escucha, sufijo)
    if not clases:
        return None
    if any(c == "todas" for c in clases):
        return "todas"
    for c in clases:
        if isinstance(c, tuple):        # ('otra', ip)
            return c
    return "loopback"


def _pid_de_fila(linea):
    """PID de una fila (ss `pid=NNN`; netstat Linux `NNN/prog`; netstat Windows, último
    token) o None."""
    m = re.search(r"pid=(\d+)", linea)
    if m:
        return int(m.group(1))
    tokens = linea.split()
    ultimo = tokens[-1] if tokens else ""
    if "/" in ultimo:                       # netstat Linux: "1234/prog"
        cab = ultimo.split("/", 1)[0]
        if cab.isdigit():
            return int(cab)
    if ultimo.isdigit():                    # netstat Windows: PID al final
        return int(ultimo)
    return None


def pid_desde_tabla(salida, puerto):
    """PID del proceso en escucha en ese puerto, o None (best-effort y multiplataforma).
    Los PID 0 y 4 de Windows cuentan como desconocidos."""
    sufijo = ":" + str(puerto)
    for linea in (salida or "").splitlines():
        if not es_fila_escucha(linea):
            continue
        if not any(t.endswith(sufijo) and len(t) > len(sufijo) for t in linea.split()):
            continue
        pid = _pid_de_fila(linea)
        if pid is not None and pid not in PIDS_DESCONOCIDOS:
            return pid
    return None


def es_no_loopback(clase_bind):
    """¿El enlace deja el servicio fuera de loopback (todas las interfaces u otra IP)?"""
    return clase_bind == "todas" or (isinstance(clase_bind, tuple) and clase_bind[0] == "otra")


def _puerto_local(linea):
    """Puerto de la primera 'dir:puerto' de la fila (la dirección local) o None."""
    for token in linea.split():
        m = re.search(r":(\d{1,5})$", token)
        if m:
            return a_puerto(m.group(1))
    return None


def puertos_en_escucha(salida):
    """Conjunto de puertos (int) en escucha según la tabla de `netstat`/`ss`."""
    puertos = set()
    for linea in (salida or "").splitlines():
        if es_fila_escucha(linea):
            p = _puerto_local(linea)
            if p is not None:
                puertos.add(p)
    return puertos


def puertos_de_pid(salida, pid):
    """Puertos en escucha atribuidos a ese PID, en el orden de la tabla y sin repetir."""
    puertos = []
    for linea in (salida or "").splitlines():
        if es_fila_escucha(linea) and _pid_de_fila(linea) == pid:
            p = _puerto_local(linea)
            if p is not None and p not in puertos:
                puertos.append(p)
    return puertos


# ----------------------------------------------------- recogida (red/SO)
def tabla_puertos():
    """Tabla de puertos en escucha (`netstat -ano` en Windows; `ss`/`netstat` en Linux).
    Nunca lanza ni usa shell: si todo falla, devuelve ''."""
    if os.name == "nt":
        ordenes = [["netstat", "-ano"]]
    else:
        ordenes = [["ss", "-ltnp"], ["netstat", "-ltnp"], ["ss", "-ltn"], ["netstat", "-ltn"]]
    for orden in ordenes:
        try:
            proc = subprocess.run(orden, capture_output=True, timeout=TIMEOUT_PROCESO)
        except (OSError, subprocess.SubprocessError):
            continue
        salida = decodificar(proc.stdout) + "\n" + decodificar(proc.stderr)
        if proc.returncode == 0 and salida.strip():
            return salida
    return ""


def ip_rutable():
    """IP local con la que el SO saldría a la red, SIN enviar ningún paquete (conecta un
    socket UDP a una IP de documentación). Devuelve la IP o None."""
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


def sondear(host, port, timeout=TIMEOUT_SONDEO):
    """¿Hay algo escuchando en host:port? connect_ex con timeout; True/False."""
    fam = socket.AF_INET6 if ":" in str(host) else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, int(port))) == 0
    except (OSError, OverflowError, ValueError):
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


def owner_proceso(pid, timeout=TIMEOUT_PROCESO):
    """Usuario del proceso (best-effort): (es_privilegiado, etiqueta) o None si no se
    puede verificar. Linux lee /proc/<pid>/status (Uid); Windows usa tasklist."""
    if pid is None or pid in PIDS_DESCONOCIDOS:
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
        proc = subprocess.run(
            ["tasklist", "/FI", f"PID eq {int(pid)}", "/V", "/FO", "CSV", "/NH"],
            capture_output=True, timeout=timeout)
        campos = re.findall(r'"([^"]*)"', decodificar(proc.stdout))
        usuario = campos[6] if len(campos) >= 7 else None
        if not usuario or usuario.upper() == "N/A":
            return None
        bajo = usuario.lower()
        privilegiado = any(m in bajo for m in ("system", "administrator", "administrador"))
        return (privilegiado, usuario)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


# ------------------------------------------------------------- cliente HTTP
@dataclass
class Respuesta:
    """Resultado de una petición. `estado` es None si no llegó a haber respuesta HTTP."""
    estado: int | None
    cabeceras: dict             # claves en minúsculas
    cuerpo: bytes
    error: str | None = None

    def texto(self):
        """Cuerpo como texto; descomprime gzip si procede y nunca lanza."""
        datos = self.cuerpo or b""
        if "gzip" in str(self.cabeceras.get("content-encoding", "")).lower():
            try:
                datos = zlib.decompressobj(zlib.MAX_WBITS | 16).decompress(datos, MAX_DESCOMPRIMIDO)
            except zlib.error:
                pass
        return datos.decode("utf-8", "replace")

    def json(self):
        """Cuerpo interpretado como JSON, o None si no lo es."""
        try:
            return json.loads(self.texto())
        except (ValueError, RecursionError):
            return None


def _ruta_vetada(ruta):
    """Rutas que ninguna comprobación debe poder pedir: un flujo que no termina y el reenvío
    a una URL arbitraria. `/cors-proxy` sin `url` sigue permitido (sirve para detectarlo)."""
    camino, _, consulta = ruta.partition("?")
    return camino == "/models/sse" or (camino == "/cors-proxy" and "url=" in consulta)


class ClienteHTTP:
    """Cliente de sondeo: garantiza el invariante de «sin efectos laterales».

    Sin proxies, sin seguir redirecciones, con tope de lectura y timeout. Solo expone
    GET, HEAD, OPTIONS y las POST de la lista blanca recibida. Registra cada petición en
    `self.peticiones` como (metodo, ruta), con la ruta relativa a la URL base y sin
    cabeceras: la clave nunca se registra. Nunca lanza por un fallo de red; la única
    excepción es `post_inocuo` con una ruta fuera de la lista, que es un error de
    programación y debe notarse.
    """

    def __init__(self, base_url, *, timeout=5, clave=None, post_permitidos=frozenset()):
        self.timeout = timeout
        self.post_permitidos = frozenset(post_permitidos)
        self.peticiones = []
        self._clave = clave
        self.esquema, self.host, self.puerto, self.prefijo = "http", "", None, ""
        try:
            partes = urllib.parse.urlsplit(str(base_url))
            self.esquema = (partes.scheme or "http").lower()
            self.host = partes.hostname or ""
            self.puerto = partes.port
            self.prefijo = partes.path.rstrip("/")
        except ValueError:
            self.host = ""

    def get(self, ruta, *, cabeceras=None, gzip=False):
        extra = dict(cabeceras or {})
        if gzip:
            extra.setdefault("Accept-Encoding", "gzip")
        return self._peticion("GET", ruta, extra)

    def head(self, ruta, *, cabeceras=None, gzip=False):
        extra = dict(cabeceras or {})
        if gzip:
            extra.setdefault("Accept-Encoding", "gzip")
        return self._peticion("HEAD", ruta, extra)

    def options(self, ruta, *, origin=None, cabeceras=None):
        """OPTIONS; con `origin` es una comprobación previa CORS completa (los middlewares
        solo la tratan como tal si también lleva Access-Control-Request-Method)."""
        extra = {}
        if origin is not None:
            extra["Origin"] = origin
            extra["Access-Control-Request-Method"] = "GET"
        extra.update(cabeceras or {})
        return self._peticion("OPTIONS", ruta, extra)

    def post_inocuo(self, ruta):
        """POST sin cuerpo a una ruta de la lista blanca del perfil. ValueError si no está."""
        if ruta not in self.post_permitidos:
            raise ValueError(f"POST no permitido: {ruta}")
        return self._peticion("POST", ruta, {})

    def _conexion(self):
        if self.esquema == "https":
            # Se audita el servidor del propio usuario, a menudo con certificado autofirmado.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return http.client.HTTPSConnection(self.host, self.puerto, timeout=self.timeout, context=ctx)
        return http.client.HTTPConnection(self.host, self.puerto, timeout=self.timeout)

    def _leer(self, resp):
        """Lee el cuerpo con tope de tamaño y de tiempo total: `timeout` solo acota cada
        lectura y un goteo o un flujo sin fin mantendrían abierta la petición."""
        limite = time.monotonic() + 2 * self.timeout
        bloques, total = [], 0
        while total < MAX_CUERPO and time.monotonic() < limite:
            bloque = resp.read1(min(65536, MAX_CUERPO - total))
            if not bloque:
                break
            bloques.append(bloque)
            total += len(bloque)
        return b"".join(bloques)

    def _peticion(self, metodo, ruta, extra):
        ruta = ruta if ruta.startswith("/") else "/" + ruta
        if _ruta_vetada(ruta):
            return Respuesta(None, {}, b"", "ruta vetada")
        self.peticiones.append((metodo, ruta))
        if not self.host:
            return Respuesta(None, {}, b"", "URL base no válida")
        cabeceras = {"User-Agent": AGENTE, "Accept": "*/*"}
        if self._clave:
            cabeceras["Authorization"] = f"Bearer {self._clave}"
        cabeceras.update(extra)
        conexion, estado, recibidas = None, None, {}
        try:
            conexion = self._conexion()
            conexion.request(metodo, self.prefijo + ruta, headers=cabeceras)
            resp = conexion.getresponse()
            estado = resp.status
            for nombre, valor in resp.getheaders():
                nombre = nombre.lower()
                recibidas[nombre] = f"{recibidas[nombre]}, {valor}" if nombre in recibidas else valor
            return Respuesta(estado, recibidas, self._leer(resp))
        except Exception as e:      # invariante: un fallo de red nunca llega al llamador
            return Respuesta(estado, recibidas, b"", type(e).__name__)
        finally:
            if conexion is not None:
                try:
                    conexion.close()
                except Exception:
                    pass
