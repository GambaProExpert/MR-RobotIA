"""
Utilidades de red y de sistema compartidas por los módulos que inventarían puertos y
enlaces de red (H2 — exposición del endpoint; H3-PUERTOS — puertos del host).

Solo biblioteca estándar. Las funciones que ejecutan procesos usan SIEMPRE una lista de
argumentos y NUNCA `shell=True` (evita inyección por la shell del host). Ninguna función
lanza al llamador: ante un fallo devuelven un valor neutro (None/""/False).
"""
from __future__ import annotations

import os
import re
import socket
import subprocess

LOOPBACK = {"127.0.0.1", "::1", "localhost"}
TODAS_IFACES = {"0.0.0.0", "::", "*"}
TIMEOUT_SONDEO = 2          # s de espera al sondear un puerto
TIMEOUT_PROCESO = 10        # s de espera a netstat/ss/tasklist


# ------------------------------------------------- funciones puras: enlace/PID
def clasificar_direccion(host):
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

    Devuelve 'loopback' | 'todas' | ('otra', ip) | None (si el puerto no aparece).
    Prefiere las líneas en escucha (LISTEN/LISTENING) y prioriza la exposición máxima.
    """
    sufijo = ":" + str(puerto)
    lineas = (salida or "").splitlines()
    escucha = [ln for ln in lineas if "listen" in ln.lower()]
    clases = clasificaciones(escucha, sufijo) or clasificaciones(lineas, sufijo)
    if not clases:
        return None
    if any(c == "todas" for c in clases):
        return "todas"
    for c in clases:
        if isinstance(c, tuple):        # ('otra', ip)
            return c
    return "loopback"


def pid_desde_tabla(salida, puerto):
    """PID del proceso en escucha en ese puerto, o None (best-effort y multiplataforma:
    ss `pid=NNN`; netstat Linux `NNN/prog`; netstat Windows PID como último token)."""
    sufijo = ":" + str(puerto)
    for linea in (salida or "").splitlines():
        if "listen" not in linea.lower():
            continue
        tokens = linea.split()
        if not any(t.endswith(sufijo) and len(t) > len(sufijo) for t in tokens):
            continue
        m = re.search(r"pid=(\d+)", linea)
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


def es_no_loopback(clase_bind):
    """¿El enlace deja el servicio fuera de loopback (todas las interfaces u otra IP)?"""
    return clase_bind == "todas" or (isinstance(clase_bind, tuple) and clase_bind[0] == "otra")


def puertos_en_escucha(salida):
    """Conjunto de puertos (int) en escucha según la tabla de `netstat`/`ss`."""
    puertos = set()
    for linea in (salida or "").splitlines():
        if "listen" not in linea.lower():
            continue
        for token in linea.split():
            m = re.search(r":(\d{1,5})$", token)
            if m:
                p = int(m.group(1))
                if 0 < p <= 65535:
                    puertos.add(p)
                break
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
            proc = subprocess.run(orden, capture_output=True, text=True, timeout=TIMEOUT_PROCESO)
        except (OSError, subprocess.SubprocessError):
            continue
        salida = (proc.stdout or "") + "\n" + (proc.stderr or "")
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
    except OSError:
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


def owner_proceso(pid, timeout=TIMEOUT_PROCESO):
    """Usuario del proceso (best-effort): (es_privilegiado, etiqueta) o None si no se
    puede verificar. Linux lee /proc/<pid>/status (Uid); Windows usa tasklist."""
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
        proc = subprocess.run(
            ["tasklist", "/FI", f"PID eq {int(pid)}", "/V", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=timeout)
        campos = re.findall(r'"([^"]*)"', proc.stdout or "")
        usuario = campos[6] if len(campos) >= 7 else None
        if not usuario or usuario.upper() == "N/A":
            return None
        bajo = usuario.lower()
        privilegiado = any(m in bajo for m in ("system", "administrator", "administrador"))
        return (privilegiado, usuario)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
