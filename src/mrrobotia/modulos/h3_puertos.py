"""
H3-PUERTOS — Puertos abiertos innecesarios o inseguros del host de inferencia.

Audita el HOST que sirve un modelo y responde a una pregunta defensiva: ¿qué puertos
escuchan en la máquina además del endpoint del modelo, y cuáles son peligrosos (bases
de datos, administración remota, caches) o simplemente innecesarios en un host cuya
única función es la inferencia? Los puertos esperados son los de los servidores que H2-ID
haya identificado más los que declare el objetivo; los canales internos que cada servidor
puede abrir no se señalan en loopback, y fuera de él son un hallazgo: no tienen autenticación.

Módulo HÍBRIDO (como H2): si el host auditado es este equipo, hace una parte PASIVA
(inventario de la tabla de puertos en escucha, sin tocar ningún servicio); si no, no la
mira, porque sería la del auditor. Solo si el sondeo activo está autorizado hace además
una parte ACTIVA que es un barrido de conexión simple (connect, no intrusivo) para
CONFIRMAR qué puertos son alcanzables desde una IP de red (no loopback). No se marca
`activo=True`: se autogatea con la regla común de `Modulo.motivo_omision_activa`.

INVARIANTE DE PRIVACIDAD: la evidencia de un hallazgo son SOLO el puerto, su enlace de
red (loopback/todas/IP) y el PID del proceso. NUNCA se conecta para leer un banner de
servicio ni se vuelca ningún dato del servicio; el propietario del proceso, cuando se
verifica, se resume como "proceso privilegiado" (sin volcar el nombre de usuario).

Separación para testabilidad: `_evaluar_puertos` (y sus auxiliares `_subir_nivel`,
`_texto_bind`, `_evidencia_puerto`) son PURAS y se prueban sin red ni herramientas; la
recogida (tabla de puertos, sondeo, propietario) se delega en `mrrobotia.red`.

Nota: el barrido activo es un connect TCP simple de la biblioteca estándar. Un backend
opcional basado en `nmap` (detección de versión/estado más fina) queda como trabajo
futuro y NO se implementa aquí.

Atacantes del modelo de amenazas: A5 (servicio alcanzable desde la red) y A3 (otros
procesos/servicios locales en el mismo host). Marcos: OWASP LLM Top 10 2025 (LLM10),
MITRE ATLAS (AML.T0049) y NIST AI 600-1 (2.9).
"""
from __future__ import annotations

from mrrobotia.modulos.h2_identificacion import destino_declarado
from mrrobotia.nucleo import Modulo, Hallazgo, Severidad
from mrrobotia.perfiles import perfil_de
from mrrobotia.red import (
    a_puerto, bind_desde_tabla, clasificar_direccion, es_host_local, es_no_loopback, ip_rutable,
    owner_proceso, pid_desde_tabla, puertos_en_escucha, sondear, tabla_puertos,
)

# --------------------------------------------------------------------- constantes
MODULO = "H3-PUERTOS"
REFS = {"owasp": "LLM10", "atlas": "AML.T0049", "nist": "2.9"}

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
def _hallazgo_interno(puerto, canal, evidencia):
    """Canal interno de un servidor fuera de loopback: no tiene autenticación."""
    return Hallazgo(
        MODULO, f"H3-PUERTOS-INTERNO-{puerto}",
        f"Canal interno {puerto}/tcp accesible fuera de loopback ({canal})",
        Severidad.ALTA, "confirmado", evidencia,
        "enlázalo a loopback o aíslalo en una red de confianza: estos canales no tienen "
        "autenticación",
        REFS)


def _evaluar_puertos(enumerados, esperados, peligrosos, expuestos_lan=(), internos=None):
    """Clasifica una lista de puertos en escucha en hallazgos (función PURA).

    `enumerados`: lista de `(puerto:int, clase_bind, pid)`, con `clase_bind` en
    {"loopback", "todas", ("otra", ip), None}. `esperados`: conjunto de puertos
    legítimos del servidor. `peligrosos`: dict puerto -> (servicio, severidad_base).
    `expuestos_lan`: puertos que el barrido activo confirmó alcanzables desde la red.
    `internos`: dict puerto -> canal interno que puede abrir alguno de los servidores.

    Reglas:
    - Peligroso: severidad_base; si el enlace no es loopback o está en `expuestos_lan`,
      se sube un nivel. Hallazgo confirmado `H3-PUERTOS-<puerto>`.
    - Inesperado (ni esperado ni peligroso): BAJA si no es loopback (o alcanzable), si
      no INFO. Hallazgo `H3-PUERTOS-INESPERADO-<puerto>`.
    - Esperado: no genera hallazgo (su exposición de red la cubre H2).
    - Canal interno: en loopback no se señala; fuera de él, ALTA `H3-PUERTOS-INTERNO-<puerto>`.
    - Si solo había puertos esperados, todos en loopback: un INFO `H3-PUERTOS-OK`.
    """
    esperados = set(esperados or ())
    expuestos_lan = set(expuestos_lan or ())
    internos = internos or {}
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
        elif puerto in internos:
            if no_loop:
                hallazgos.append(_hallazgo_interno(puerto, internos[puerto], evidencia))
                hubo_hallazgo = True
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
    PELIGROSOS = PELIGROSOS

    # ----------------------------------------------------------- configuración
    def _config(self, objetivo):
        """Deriva (host, esperados, peligrosos, internos). Lo que se espera sale de lo que H2-ID
        haya identificado y de lo que declare el objetivo, nunca de deducir el servidor por el
        puerto: sin contexto, el módulo trabaja solo con lo declarado."""
        destino = destino_declarado(objetivo)
        puertos_cfg = objetivo.get("puertos", {}) or {}
        declarados = [destino.puerto, *(puertos_cfg.get("esperados") or ())]
        esperados = {p for p in map(a_puerto, declarados) if p is not None}
        internos = {}
        for servidor in (self.contexto.servidores if self.contexto is not None else ()):
            if servidor.puerto is not None:
                esperados.add(servidor.puerto)
            internos.update(perfil_de(servidor).puertos_internos)
        extra = _normalizar_extra(puertos_cfg.get("extra_peligrosos", {}))
        peligrosos = {**PELIGROSOS, **extra}
        return destino.host, esperados, peligrosos, internos

    # ----------------------------------------------------------- barrido activo
    def _barrido_activo(self, host, enumerados, esperados, peligrosos, internos):
        """Barrido de conexión simple (connect, no intrusivo) para confirmar qué puertos
        son alcanzables desde una IP de RED (no loopback). Devuelve (expuestos_lan,
        hallazgos_extra). Se prueba el host objetivo cuando este NO es loopback, y si lo
        es, la IP rutable del propio equipo; nunca las dos: la IP del auditor no dice
        nada de un host ajeno, y lo que solo contesta por loopback no cuenta como expuesto."""
        puertos_tabla = {p for p, _, _ in enumerados}
        direccion = host if isinstance(clasificar_direccion(host), tuple) else ip_rutable()
        if not direccion or clasificar_direccion(direccion) == "loopback":
            return set(), []
        # Desde el propio equipo no se puede afirmar que llegue nadie de fuera.
        propio = es_host_local(direccion)
        alcance = "responde en la IP de red de este equipo" if propio else "alcanzable desde el equipo auditor"
        nota = "; no aparecía en la tabla de puertos local" if propio else ""

        expuestos = set()
        extra = []
        for p in sorted(set(peligrosos) | set(esperados) | set(internos)):
            if not sondear(direccion, p):
                continue
            expuestos.add(p)
            if p in puertos_tabla:
                continue
            # Alcanzable por red y sin fila en la tabla (no se ha leído, porque el host es
            # ajeno, o está enlazado solo a la interfaz externa): se marca desde el barrido.
            evidencia = f"{p}/tcp {alcance} (barrido activo){nota}"
            if p in peligrosos:
                servicio, sev_base = peligrosos[p]
                extra.append(Hallazgo(
                    MODULO, f"H3-PUERTOS-{p}",
                    f"Puerto inseguro {p}/tcp {alcance} ({servicio})",
                    _subir_nivel(sev_base), "confirmado", evidencia,
                    "cierra/filtra el puerto o enlázalo a loopback; no es necesario en un "
                    "host de inferencia",
                    REFS))
            elif p in internos and p not in esperados:
                extra.append(_hallazgo_interno(p, internos[p], evidencia))
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
    def _enumerar(self, hallazgos):
        """Puertos en escucha de este equipo como [(puerto, enlace, pid)]."""
        salida = tabla_puertos()
        if not salida:
            hallazgos.append(Hallazgo(
                MODULO, "H3-PUERTOS-SIN-TABLA",
                "No se pudo obtener la tabla de puertos del host",
                Severidad.INFO, "sin_concluir",
                "no se pudo obtener la tabla de puertos; revisa a mano con netstat/ss",
                "Comprueba a mano con 'netstat -ano' (Windows) o 'ss -ltnp' (Linux) qué "
                "puertos escuchan en el host.", REFS))
            return []
        return [(p, bind_desde_tabla(salida, p), pid_desde_tabla(salida, p))
                for p in sorted(puertos_en_escucha(salida))]

    def ejecutar(self, objetivo):
        host, esperados, peligrosos, internos = self._config(objetivo)
        local = es_host_local(host)
        hallazgos = []

        # ---- PASIVO: solo la tabla del host auditado, nunca la del auditor ---------
        if local:
            enumerados = self._enumerar(hallazgos)
        else:
            enumerados = []
            hallazgos.append(Hallazgo(
                MODULO, "H3-PUERTOS-NO-LOCAL",
                "No se ha inspeccionado la tabla de puertos del host",
                Severidad.INFO, "informativo",
                "el host auditado no es este equipo: su tabla de puertos no está aquí",
                "Ejecuta MRRobotIA en ese host para inventariar sus puertos; desde aquí, el "
                "barrido activo solo prueba por conexión los puertos conocidos.", REFS))

        # ---- GATING ACTIVO -------------------------------------------------------
        expuestos_lan = set()
        extra_barrido = []
        omision = self.motivo_omision_activa(objetivo, local)
        if omision:
            hallazgos.append(Hallazgo(
                MODULO, "H3-PUERTOS-ACTIVO-OMITIDO", "Barrido activo de puertos omitido",
                Severidad.INFO, "informativo", omision,
                "El barrido activo exige --permitir-activos y permitir_activos=true y, en un "
                "host no local, autorizacion.confirmo_no_local=true con permiso escrito.", REFS))
        else:
            try:
                expuestos_lan, extra_barrido = self._barrido_activo(host, enumerados, esperados, peligrosos, internos)
            except Exception as e:
                hallazgos.append(Hallazgo(
                    MODULO, "H3-PUERTOS-ERROR", "Error durante el barrido activo de puertos",
                    Severidad.INFO, "informativo", type(e).__name__,
                    "Revisa la configuración de 'puertos' en el objetivo y el estado del host.",
                    REFS))
                expuestos_lan, extra_barrido = set(), []

        # ---- EVALUACIÓN (pura) + extras del barrido ------------------------------
        hallazgos.extend(_evaluar_puertos(enumerados, esperados, peligrosos, expuestos_lan, internos))
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
