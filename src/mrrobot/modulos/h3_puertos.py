"""
H3-PUERTOS — Puertos abiertos innecesarios o inseguros del host de inferencia.

Audita el HOST que sirve un modelo abierto con vLLM o llama.cpp y responde a una
pregunta defensiva: ¿qué puertos escuchan en la máquina además del endpoint del
modelo, y cuáles son peligrosos (bases de datos, administración remota, caches) o
simplemente innecesarios en un host cuya única función es la inferencia?

Módulo HÍBRIDO (como H2): siempre hace una parte PASIVA (inventario local de la tabla
de puertos en escucha: `netstat`/`ss`, sin tocar ningún servicio) y, solo si el sondeo
activo está autorizado, una parte ACTIVA que es un barrido de conexión simple (connect,
no intrusivo) para CONFIRMAR qué puertos son alcanzables desde una IP de red (no
loopback). No se marca `activo=True`: se autogatea leyendo `self.activos_ok` (que el CLI
pone a True con --permitir-activos + permitir_activos) y, para hosts no locales, exige
además `autorizacion.confirmo_no_local`, igual que el núcleo y H2.

INVARIANTE DE PRIVACIDAD: la evidencia de un hallazgo son SOLO el puerto, su enlace de
red (loopback/todas/IP) y el PID del proceso. NUNCA se conecta para leer un banner de
servicio ni se vuelca ningún dato del servicio; el propietario del proceso, cuando se
verifica, se resume como "proceso privilegiado" (sin volcar el nombre de usuario).

Separación para testabilidad: `_evaluar_puertos` (y sus auxiliares `_subir_nivel`,
`_texto_bind`, `_evidencia_puerto`) son PURAS y se prueban sin red ni herramientas; la
recogida (tabla de puertos, sondeo, propietario) se delega en `mrrobot.red`.

Nota: el barrido activo es un connect TCP simple de la biblioteca estándar. Un backend
opcional basado en `nmap` (detección de versión/estado más fina) queda como trabajo
futuro y NO se implementa aquí.

Atacantes del modelo de amenazas: A5 (servicio alcanzable desde la red) y A3 (otros
procesos/servicios locales en el mismo host). Marcos: OWASP LLM Top 10 2025 (LLM10),
MITRE ATLAS (AML.T0049) y NIST AI 600-1 (2.9).
"""
from __future__ import annotations

import urllib.parse

from mrrobot.nucleo import Modulo, Hallazgo, Severidad
from mrrobot.red import (
    tabla_puertos, bind_desde_tabla, pid_desde_tabla, puertos_en_escucha,
    ip_rutable, sondear, owner_proceso, es_no_loopback, LOOPBACK,
)

# --------------------------------------------------------------------- constantes
MODULO = "H3-PUERTOS"
REFS = {"owasp": "LLM10", "atlas": "AML.T0049", "nist": "2.9"}

# Puertos legítimos por tipo de servidor de inferencia (no se señalan por existir).
# 8265 es el dashboard de Ray que levanta vLLM en despliegues multinodo.
ESPERADOS = {
    "llama.cpp": {8080},
    "vllm": {8000, 8265},
}

# Puertos peligrosos: puerto -> (servicio, severidad_base). La severidad_base es la que
# corresponde al servicio escuchando en loopback; si el enlace sale de loopback (o el
# barrido activo lo confirma alcanzable desde la red) se sube un nivel.
PELIGROSOS = {
    23: ("Telnet", Severidad.CRITICA),
    2375: ("Docker API sin TLS", Severidad.CRITICA),
    6379: ("Redis", Severidad.CRITICA),
    21: ("FTP", Severidad.ALTA),
    20: ("FTP-data", Severidad.ALTA),
    139: ("SMB", Severidad.ALTA),
    445: ("SMB", Severidad.ALTA),
    3389: ("RDP", Severidad.ALTA),
    5900: ("VNC", Severidad.ALTA),
    5901: ("VNC", Severidad.ALTA),
    3306: ("MySQL", Severidad.ALTA),
    5432: ("PostgreSQL", Severidad.ALTA),
    1433: ("MSSQL", Severidad.ALTA),
    27017: ("MongoDB", Severidad.ALTA),
    9200: ("Elasticsearch", Severidad.ALTA),
    9300: ("Elasticsearch", Severidad.ALTA),
    11211: ("Memcached", Severidad.ALTA),
    8888: ("Jupyter", Severidad.ALTA),
    2379: ("etcd", Severidad.ALTA),
    2380: ("etcd", Severidad.ALTA),
    135: ("MSRPC", Severidad.MEDIA),
    25: ("SMTP", Severidad.MEDIA),
    110: ("POP3", Severidad.MEDIA),
    143: ("IMAP", Severidad.MEDIA),
    161: ("SNMP", Severidad.MEDIA),
    6006: ("TensorBoard", Severidad.MEDIA),
}

# Puertos que el barrido activo intenta alcanzar: todos los peligrosos + los esperados
# de ambos servidores (para confirmar alcanzabilidad desde la red sin depender del tipo).
PUERTOS_SONDEO = sorted(set(PELIGROSOS) | {8080, 8000, 8265})


# ----------------------------------------------------- funciones puras: auxiliares
def _subir_nivel(sev):
    """Sube la severidad un nivel, con tope en CRITICA (ALTA->CRITICA, MEDIA->ALTA...)."""
    return Severidad(min(int(sev) + 1, int(Severidad.CRITICA)))


def _texto_bind(clase_bind):
    """Texto legible del enlace para la evidencia: loopback | todas | <ip> | desconocido.
    NUNCA aporta datos del servicio, solo su exposición de red."""
    if clase_bind == "loopback":
        return "loopback"
    if clase_bind == "todas":
        return "todas"
    if isinstance(clase_bind, tuple) and len(clase_bind) == 2 and clase_bind[0] == "otra":
        return str(clase_bind[1])
    return "desconocido"


def _evidencia_puerto(puerto, clase_bind, pid):
    """Evidencia mínima y reproducible: puerto + enlace + PID. Sin banners ni datos."""
    pid_txt = str(pid) if pid is not None else "?"
    return f"{puerto}/tcp en escucha; bind {_texto_bind(clase_bind)}; pid {pid_txt}"


# ----------------------------------------------------- función pura: evaluación
def _evaluar_puertos(enumerados, esperados, peligrosos, expuestos_lan=()):
    """Clasifica una lista de puertos en escucha en hallazgos (función PURA).

    `enumerados`: lista de `(puerto:int, clase_bind, pid)`, con `clase_bind` en
    {"loopback", "todas", ("otra", ip), None}. `esperados`: conjunto de puertos
    legítimos del servidor. `peligrosos`: dict puerto -> (servicio, severidad_base).
    `expuestos_lan`: puertos que el barrido activo confirmó alcanzables desde la red.

    Reglas:
    - Peligroso: severidad_base; si el enlace no es loopback o está en `expuestos_lan`,
      se sube un nivel. Hallazgo confirmado `H3-PUERTOS-<puerto>`.
    - Inesperado (ni esperado ni peligroso): BAJA si no es loopback (o alcanzable), si
      no INFO. Hallazgo `H3-PUERTOS-INESPERADO-<puerto>`.
    - Esperado: no genera hallazgo (su exposición de red la cubre H2).
    - Si solo había puertos esperados, todos en loopback: un INFO `H3-PUERTOS-OK`.
    """
    esperados = set(esperados or ())
    expuestos_lan = set(expuestos_lan or ())
    hallazgos = []
    hubo_hallazgo = False            # ¿algún peligro o inesperado?
    todo_esperado_loopback = True    # ¿todos los puertos son esperados y en loopback?

    for puerto, clase_bind, pid in enumerados:
        no_loop = es_no_loopback(clase_bind) or (puerto in expuestos_lan)
        evidencia = _evidencia_puerto(puerto, clase_bind, pid)

        if puerto in peligrosos:
            servicio, sev_base = peligrosos[puerto]
            sev = _subir_nivel(sev_base) if no_loop else sev_base
            hallazgos.append(Hallazgo(
                MODULO, f"H3-PUERTOS-{puerto}",
                f"Puerto inseguro {puerto}/tcp en escucha ({servicio})",
                sev, "confirmado", evidencia,
                "cierra/filtra el puerto o enlázalo a loopback; no es necesario en un "
                "host de inferencia",
                REFS))
            hubo_hallazgo = True
            todo_esperado_loopback = False
        elif puerto in esperados:
            # Puerto legítimo del servidor de inferencia: no se señala por existir. Su
            # bind (si sale de loopback) lo evalúa H2; aquí solo cuenta para el OK.
            if clase_bind != "loopback":
                todo_esperado_loopback = False
        else:
            sev = Severidad.BAJA if no_loop else Severidad.INFO
            hallazgos.append(Hallazgo(
                MODULO, f"H3-PUERTOS-INESPERADO-{puerto}",
                f"Puerto inesperado {puerto}/tcp en escucha",
                sev, "confirmado", evidencia,
                "revisa si este servicio debe estar en el host de inferencia",
                REFS))
            hubo_hallazgo = True
            todo_esperado_loopback = False

    if enumerados and not hubo_hallazgo and todo_esperado_loopback:
        hallazgos.append(Hallazgo(
            MODULO, "H3-PUERTOS-OK",
            "Solo escuchan los puertos esperados en loopback",
            Severidad.INFO, "informativo",
            "solo escuchan los puertos esperados en loopback",
            "", REFS))
    return hallazgos


# ------------------------------------------------------------------------- módulo
class H3Puertos(Modulo):
    nombre = "H3-PUERTOS"
    titulo = "Puertos abiertos innecesarios o inseguros del host"
    activo = False               # HÍBRIDO: se ejecuta siempre y autogatea con self.activos_ok
    etiqueta_escaneo = "puertos"

    # Constantes accesibles también como atributos del objeto (comodidad/trazabilidad).
    REFS = REFS
    ESPERADOS = ESPERADOS
    PELIGROSOS = PELIGROSOS
    PUERTOS_SONDEO = PUERTOS_SONDEO

    # ----------------------------------------------------------- configuración
    def _config(self, objetivo):
        """Deriva (host, servidor, esperados, peligrosos) del objetivo. El servidor se
        toma de `objetivo['servidor']` o se infiere del puerto del endpoint."""
        endpoint = objetivo.get("endpoint")
        servidor = objetivo.get("servidor")
        host = objetivo.get("host") or "127.0.0.1"
        if endpoint:
            p = urllib.parse.urlparse(endpoint)
            host = p.hostname or host
            if servidor is None:
                if p.port == 8000:
                    servidor = "vllm"
                elif p.port == 8080:
                    servidor = "llama.cpp"

        puertos_cfg = objetivo.get("puertos", {}) or {}
        esperados = set(puertos_cfg.get("esperados") or ()) or ESPERADOS.get(servidor, set())
        extra = _normalizar_extra(puertos_cfg.get("extra_peligrosos", {}))
        peligrosos = {**PELIGROSOS, **extra}
        return host, servidor, esperados, peligrosos

    # ----------------------------------------------------------- barrido activo
    def _barrido_activo(self, host, enumerados, peligrosos):
        """Barrido de conexión simple (connect, no intrusivo) para confirmar qué puertos
        son alcanzables desde una IP de RED (no loopback). Devuelve (expuestos_lan,
        hallazgos_extra). Un puerto solo cuenta como expuesto_lan si responde en el host
        objetivo cuando este NO es loopback, o en la IP rutable del propio equipo; así no
        se marca como expuesto algo que solo contesta por loopback."""
        puertos_tabla = {p for p, _, _ in enumerados}
        host_externo = host if host not in LOOPBACK else None
        ip = ip_rutable()
        ip_externa = ip if (ip and ip not in LOOPBACK) else None

        expuestos = set()
        extra = []
        for p in PUERTOS_SONDEO:
            alcanzable = False
            if host_externo and sondear(host_externo, p):
                alcanzable = True
            elif ip_externa and sondear(ip_externa, p):
                alcanzable = True
            if not alcanzable:
                continue
            expuestos.add(p)
            # Peligroso alcanzable desde la red que NO aparecía en la tabla local
            # (p. ej. enlazado solo a la interfaz externa): márcalo desde el barrido.
            if p in peligrosos and p not in puertos_tabla:
                servicio, sev_base = peligrosos[p]
                extra.append(Hallazgo(
                    MODULO, f"H3-PUERTOS-{p}",
                    f"Puerto inseguro {p}/tcp alcanzable desde la red ({servicio})",
                    _subir_nivel(sev_base), "confirmado",
                    f"{p}/tcp alcanzable desde la red (barrido activo); no aparecía en "
                    "la tabla de puertos local",
                    "cierra/filtra el puerto o enlázalo a loopback; no es necesario en un "
                    "host de inferencia",
                    REFS))
        return expuestos, extra

    # ----------------------------------------------------------- enriquecer owner
    def _enriquecer_owner(self, hallazgos, enumerados, peligrosos):
        """Best-effort: si un puerto peligroso de la tabla corre como root/privilegiado,
        lo anota en su evidencia. Solo el hecho (privilegiado), nunca el nombre de usuario."""
        por_id = {}
        for h in hallazgos:
            if h is not None:
                por_id.setdefault(h.id, h)
        for puerto, _clase, pid in enumerados:
            if puerto not in peligrosos or pid is None:
                continue
            h = por_id.get(f"H3-PUERTOS-{puerto}")
            if h is None:
                continue
            try:
                info = owner_proceso(pid)
            except Exception:
                info = None
            if info and info[0]:                     # (es_privilegiado, etiqueta)
                h.evidencia += "; proceso privilegiado"

    # --------------------------------------------------------------- orquestación
    def ejecutar(self, objetivo):
        host, _servidor, esperados, peligrosos = self._config(objetivo)
        hallazgos = []

        # ---- PASIVO (siempre): tabla de puertos en escucha -----------------------
        salida = tabla_puertos()
        if not salida:
            hallazgos.append(Hallazgo(
                MODULO, "H3-PUERTOS-SIN-TABLA",
                "No se pudo obtener la tabla de puertos del host",
                Severidad.INFO, "informativo",
                "no se pudo obtener la tabla de puertos; revisa a mano con netstat/ss",
                "Comprueba a mano con 'netstat -ano' (Windows) o 'ss -ltnp' (Linux) qué "
                "puertos escuchan en el host.", REFS))
            enumerados = []
        else:
            enumerados = []
            for p in sorted(puertos_en_escucha(salida)):
                clase = bind_desde_tabla(salida, p)
                pid = pid_desde_tabla(salida, p)
                enumerados.append((p, clase, pid))

        # ---- GATING ACTIVO -------------------------------------------------------
        expuestos_lan = set()
        extra_barrido = []
        activos = getattr(self, "activos_ok", False)
        no_local = host not in LOOPBACK
        if no_local and objetivo.get("autorizacion", {}).get("confirmo_no_local") is not True:
            hallazgos.append(Hallazgo(
                MODULO, "H3-PUERTOS-ACTIVO-OMITIDO", "Barrido activo de puertos omitido",
                Severidad.INFO, "informativo",
                "host no local sin confirmo_no_local",
                "Marca autorizacion.confirmo_no_local=true solo con permiso escrito para "
                "sondear un host no local.", REFS))
        elif not activos:
            hallazgos.append(Hallazgo(
                MODULO, "H3-PUERTOS-ACTIVO-OMITIDO", "Barrido activo de puertos omitido",
                Severidad.INFO, "informativo",
                "barrido activo omitido: requiere --permitir-activos y permitir_activos=true",
                "Habilita --permitir-activos y permitir_activos=true en el objetivo para "
                "el barrido activo de puertos.", REFS))
        else:
            try:
                expuestos_lan, extra_barrido = self._barrido_activo(host, enumerados, peligrosos)
            except Exception as e:
                hallazgos.append(Hallazgo(
                    MODULO, "H3-PUERTOS-ERROR", "Error durante el barrido activo de puertos",
                    Severidad.INFO, "informativo", type(e).__name__,
                    "Revisa la configuración de 'puertos' en el objetivo y el estado del host.",
                    REFS))
                expuestos_lan, extra_barrido = set(), []

        # ---- EVALUACIÓN (pura) + extras del barrido ------------------------------
        hallazgos.extend(_evaluar_puertos(enumerados, esperados, peligrosos, expuestos_lan))
        hallazgos.extend(extra_barrido)

        # ---- propietario del proceso (best-effort) -------------------------------
        self._enriquecer_owner(hallazgos, enumerados, peligrosos)

        return [h for h in hallazgos if h is not None]


# ----------------------------------------------------- normalización de extras
def _a_severidad(valor, por_defecto=Severidad.ALTA):
    """Convierte un entero o un nombre ('ALTA', 'critica'...) en Severidad; si no se
    reconoce, devuelve `por_defecto`."""
    if isinstance(valor, Severidad):
        return valor
    if isinstance(valor, bool):
        return por_defecto
    if isinstance(valor, int):
        try:
            return Severidad(valor)
        except ValueError:
            return por_defecto
    if isinstance(valor, str):
        try:
            return Severidad[valor.strip().upper()]
        except KeyError:
            return por_defecto
    return por_defecto


def _normalizar_extra(extra):
    """Normaliza `extra_peligrosos` del objetivo (que viene de JSON) a {puerto:int ->
    (servicio:str, Severidad)}, de modo que el merge con PELIGROSOS use claves int y
    severidades comparables. Ignora entradas malformadas sin lanzar."""
    norm = {}
    if not isinstance(extra, dict):
        return norm
    for clave, valor in extra.items():
        try:
            puerto = int(clave)
        except (TypeError, ValueError):
            continue
        servicio, sev = "servicio declarado", Severidad.ALTA
        if isinstance(valor, (list, tuple)):
            if len(valor) >= 1 and valor[0] is not None:
                servicio = str(valor[0])
            if len(valor) >= 2:
                sev = _a_severidad(valor[1])
        elif isinstance(valor, str):
            servicio = valor
        elif isinstance(valor, dict):
            if valor.get("servicio"):
                servicio = str(valor["servicio"])
            if "severidad" in valor:
                sev = _a_severidad(valor["severidad"])
        norm[puerto] = (servicio, sev)
    return norm
