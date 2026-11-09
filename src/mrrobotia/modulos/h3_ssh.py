"""
H3-SSH — Endurecimiento de SSH del host que sirve el modelo.

Módulo HÍBRIDO: siempre hace una parte PASIVA (lee el `sshd_config` del host y
evalúa sus directivas contra un perfil tipo CIS Benchmark, sin tocar el servicio) y,
solo si el sondeo activo está autorizado, una parte ACTIVA que delega en `ssh-audit`
para auditar los algoritmos negociados por el servidor SSH en vivo.

Autogating (igual que H2): NO se marca `activo=True` —así el CLI ejecuta siempre la
parte pasiva—, sino que se lee `self.activos_ok` (que el CLI pone a True con
--permitir-activos + permitir_activos) para decidir si corre la parte activa. Para
hosts no locales exige, además, autorizacion.confirmo_no_local, como el núcleo. Si el
host no es este equipo, tampoco se lee ningún `sshd_config`: sería el del auditor.

INVARIANTE DE PRIVACIDAD (crítico): la evidencia de los hallazgos son SOLO nombres de
directiva + sus valores de política (yes/no, listas de algoritmos, números) y, en la
parte activa, nombres de algoritmo + el texto genérico de la nota de ssh-audit. NUNCA
se vuelca una clave privada, una host key ni su huella (la sección `fingerprints` de
ssh-audit se ignora a propósito), ni ningún secreto: el informe de auditoría no debe
convertirse él mismo en una filtración.

Diseño GENERAL (no depende de ningún caso del TFG): solo biblioteca estándar (os, re,
json) y `mrrobotia.herramientas` para orquestar ssh-audit (nunca shell=True).

Separación para testabilidad: `_evaluar_sshd(cfg)` y `_evaluar_sshaudit(obj)` son
funciones PURAS y se prueban sin servidor SSH ni ssh-audit instalado; los métodos del
objeto (`_ruta_sshd`, `_leer_config`, `_activo`, `ejecutar`) son los que tocan disco /
procesos.

Atacantes del modelo de amenazas: A5 (acceso al servicio por red) y A3 (interno con
acceso local). Marcos: OWASP LLM Top 10 2025 (LLM10 exposición), MITRE ATLAS
(AML.T0049) y NIST AI 600-1 (2.9).
"""
from __future__ import annotations

import json
import os
import re

from mrrobotia import herramientas, red
from mrrobotia.nucleo import Modulo, Hallazgo, Severidad

# --------------------------------------------------------------------- constantes
REFS = {"owasp": "LLM10", "atlas": "AML.T0049", "nist": "2.9"}

# Rutas por defecto del sshd_config según el SO, si el objetivo no declara una.
_RUTA_SSHD_NT = r"C:\ProgramData\ssh\sshd_config"
_RUTA_SSHD_POSIX = "/etc/ssh/sshd_config"

# Tope de hallazgos de la parte activa (algoritmos/CVE); el resto se resume en un INFO.
MAX_ACTIVOS = 20
SSH_AUDIT = herramientas.Herramienta(
    "ssh-audit", "ssh-audit", instalar_con="pip install ssh-audit", refs=REFS)

# CVE que ssh-audit puede señalar en el texto de las notas aunque su campo `cves` esté
# vacío (la asociación CVE↔versión se retiró en ssh-audit 3.3.0).
_RE_CVE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


# ----------------------------------------------------------- auxiliares (puros)
def _estado(sev):
    """INFO → 'informativo'; cualquier severidad mayor → 'confirmado'."""
    return "informativo" if sev == Severidad.INFO else "confirmado"


def _recorta(texto, n=300):
    """Recorta a `n` caracteres con un '…' final; nunca None."""
    texto = (texto or "").strip()
    return texto if len(texto) <= n else texto[: n - 1] + "…"


def _conf(directiva, valor, sev, titulo, rec):
    """Hallazgo de desviación de una directiva de sshd_config. La evidencia es
    SIEMPRE 'directiva=valor' (política, nunca un secreto)."""
    return Hallazgo(
        "H3-SSH", "H3-SSH-CONF-" + directiva.upper(), titulo,
        sev, _estado(sev), f"{directiva}={valor}", rec, REFS)


def _segundos(valor):
    """LoginGraceTime a segundos: admite sufijos s/m/h (p. ej. '2m'). None si no parsea."""
    s = str(valor).strip().lower()
    if not s:
        return None
    mult = 1
    if s[-1] in "smh":
        mult = {"s": 1, "m": 60, "h": 3600}[s[-1]]
        s = s[:-1]
    try:
        return int(s) * mult
    except ValueError:
        return None


def _menciona_cve(texto):
    """¿El texto de una nota alude a un CVE o a un ataque con nombre (Terrapin/DHEat)?"""
    t = (texto or "").lower()
    return bool(_RE_CVE.search(texto or "")) or "terrapin" in t or "dheat" in t


def _lista_textos(valor):
    """Aplana None / str / dict / lista(anidada) a una lista de cadenas no vacías.
    Tolerante al formato: `notes` trae listas de strings, pero `additional_notes`
    puede traer strings o dicts según la versión de ssh-audit."""
    out = []
    if valor is None:
        return out
    if isinstance(valor, str):
        if valor.strip():
            out.append(valor.strip())
        return out
    if isinstance(valor, dict):
        for v in valor.values():
            out.extend(_lista_textos(v))
        return out
    if isinstance(valor, (list, tuple)):
        for x in valor:
            out.extend(_lista_textos(x))
        return out
    s = str(valor).strip()
    if s:
        out.append(s)
    return out


def _cve_campos(c):
    """(nombre, descripción) de un elemento de la lista `cves` (dict o str)."""
    if isinstance(c, dict):
        nombre = c.get("name") or c.get("cve") or c.get("id") or ""
        desc = c.get("description") or c.get("desc") or ""
        return str(nombre), str(desc)
    if isinstance(c, str):
        return c, ""
    return "", ""


# ------------------------------------------------------- evaluación de sshd_config
def _evaluar_sshd(cfg):
    """Evalúa un `sshd_config` ya parseado (dict {directiva_minuscula: valor}) contra
    un perfil de endurecimiento tipo CIS Benchmark. Función PURA (testeable): un
    `Hallazgo` por desviación; si no hay ninguna y había directivas, un INFO
    'H3-SSH-CONF-OK'. La evidencia es siempre política (directiva=valor), nunca un
    secreto."""
    hallazgos = []

    def low(clave):
        v = cfg.get(clave)
        return v.strip().lower() if isinstance(v, str) else None

    # PermitRootLogin: 'yes' permite root con contraseña -> ALTA; 'prohibit-password'
    # / 'without-password' permite root con clave pública -> MEDIA.
    v = cfg.get("permitrootlogin")
    lv = low("permitrootlogin")
    if lv == "yes":
        hallazgos.append(_conf(
            "permitrootlogin", v, Severidad.ALTA,
            "El acceso directo de root por SSH está permitido (con contraseña)",
            "Pon 'PermitRootLogin no' y entra con un usuario sin privilegios + sudo (A3)."))
    elif lv in ("prohibit-password", "without-password"):
        hallazgos.append(_conf(
            "permitrootlogin", v, Severidad.MEDIA,
            "root puede entrar por SSH con clave pública",
            "Pon 'PermitRootLogin no': usa un usuario sin privilegios y sudo en vez de root."))

    # PermitEmptyPasswords: 'yes' -> CRITICA.
    v = cfg.get("permitemptypasswords")
    if low("permitemptypasswords") == "yes":
        hallazgos.append(_conf(
            "permitemptypasswords", v, Severidad.CRITICA,
            "SSH acepta cuentas con contraseña vacía",
            "Pon 'PermitEmptyPasswords no': una contraseña vacía deja la cuenta abierta a cualquiera."))

    # PasswordAuthentication: 'yes' -> MEDIA (recomendar claves).
    v = cfg.get("passwordauthentication")
    if low("passwordauthentication") == "yes":
        hallazgos.append(_conf(
            "passwordauthentication", v, Severidad.MEDIA,
            "SSH permite autenticación por contraseña",
            "Pon 'PasswordAuthentication no' y usa autenticación por clave pública (resiste fuerza bruta)."))

    # PubkeyAuthentication: 'no' -> MEDIA.
    v = cfg.get("pubkeyauthentication")
    if low("pubkeyauthentication") == "no":
        hallazgos.append(_conf(
            "pubkeyauthentication", v, Severidad.MEDIA,
            "La autenticación por clave pública está deshabilitada",
            "Pon 'PubkeyAuthentication yes': es el método recomendado frente a contraseñas."))

    # Protocol: contiene la versión 1 (SSHv1, roto) -> CRITICA.
    v = cfg.get("protocol")
    if isinstance(v, str) and "1" in [t for t in re.split(r"[,\s]+", v.strip()) if t]:
        hallazgos.append(_conf(
            "protocol", v, Severidad.CRITICA,
            "El servidor admite el protocolo SSHv1 (obsoleto e inseguro)",
            "Elimina la directiva 'Protocol' o déjala en '2': SSHv1 tiene fallos criptográficos conocidos."))

    # Ciphers: cifrados en modo CBC / arcfour / 3DES -> ALTA.
    v = cfg.get("ciphers")
    lv = low("ciphers")
    if lv and ("cbc" in lv or "arcfour" in lv or "3des" in lv):
        hallazgos.append(_conf(
            "ciphers", v, Severidad.ALTA,
            "Hay cifrados SSH débiles habilitados (CBC/arcfour/3DES)",
            "Usa solo cifrados AES-GCM/ChaCha20 (chacha20-poly1305@openssh.com, aes256-gcm@openssh.com, aes128-gcm@openssh.com)."))

    # MACs: HMAC-MD5, truncadas (-96) o basadas en SHA-1 -> ALTA.
    v = cfg.get("macs")
    lv = low("macs")
    if lv and ("hmac-md5" in lv or "-96" in lv or "sha1" in lv):
        hallazgos.append(_conf(
            "macs", v, Severidad.ALTA,
            "Hay MAC SSH débiles habilitadas (MD5, truncadas o SHA-1)",
            "Usa MAC ETM con SHA-2 (hmac-sha2-512-etm@openssh.com, hmac-sha2-256-etm@openssh.com)."))

    # KexAlgorithms: grupos DH débiles o SHA-1 -> ALTA.
    v = cfg.get("kexalgorithms")
    lv = low("kexalgorithms")
    if lv and ("group1" in lv or "group14-sha1" in lv or "group-exchange-sha1" in lv):
        hallazgos.append(_conf(
            "kexalgorithms", v, Severidad.ALTA,
            "Hay intercambios de clave SSH débiles habilitados (grupos DH pequeños o SHA-1)",
            "Usa curve25519-sha256 o diffie-hellman-group16/18-sha512; evita group1 y cualquier '*-sha1'."))

    # MaxAuthTries: >4 -> MEDIA; ausente -> BAJA.
    v = cfg.get("maxauthtries")
    if v is None:
        hallazgos.append(Hallazgo(
            "H3-SSH", "H3-SSH-CONF-MAXAUTHTRIES",
            "No se fija MaxAuthTries (límite de intentos de autenticación)",
            Severidad.BAJA, "confirmado", "maxauthtries ausente",
            "Fija 'MaxAuthTries 4' o menos para limitar la fuerza bruta por conexión.", REFS))
    else:
        try:
            n = int(str(v).strip())
        except ValueError:
            n = None
        if n is not None and n > 4:
            hallazgos.append(_conf(
                "maxauthtries", v, Severidad.MEDIA,
                "MaxAuthTries permite demasiados intentos de autenticación",
                "Baja a 'MaxAuthTries 4' o menos para dificultar la fuerza bruta."))

    # LoginGraceTime: >60 s -> BAJA; ausente -> BAJA.
    v = cfg.get("logingracetime")
    if v is None:
        hallazgos.append(Hallazgo(
            "H3-SSH", "H3-SSH-CONF-LOGINGRACETIME",
            "No se fija LoginGraceTime (ventana para autenticarse)",
            Severidad.BAJA, "confirmado", "logingracetime ausente",
            "Fija 'LoginGraceTime 30' (o 60) para cerrar antes las conexiones sin autenticar.", REFS))
    else:
        seg = _segundos(v)
        if seg is not None and seg > 60:
            hallazgos.append(_conf(
                "logingracetime", v, Severidad.BAJA,
                "LoginGraceTime deja una ventana amplia sin autenticar",
                "Baja LoginGraceTime a 30-60 s: limita las conexiones a medio autenticar (defensa anti-DoS)."))

    # AllowUsers / AllowGroups: ninguna presente -> BAJA (recomendar lista blanca).
    if "allowusers" not in cfg and "allowgroups" not in cfg:
        hallazgos.append(Hallazgo(
            "H3-SSH", "H3-SSH-CONF-ALLOWLIST",
            "No hay lista blanca de usuarios/grupos para SSH",
            Severidad.BAJA, "confirmado", "ni allowusers ni allowgroups definidos",
            "Define 'AllowUsers' o 'AllowGroups' con las cuentas que de verdad deben acceder por SSH.", REFS))

    # X11Forwarding: 'yes' -> BAJA.
    v = cfg.get("x11forwarding")
    if low("x11forwarding") == "yes":
        hallazgos.append(_conf(
            "x11forwarding", v, Severidad.BAJA,
            "El reenvío de X11 está habilitado",
            "Pon 'X11Forwarding no' salvo que lo necesites: amplía la superficie de ataque hacia el cliente."))

    # Sin desviaciones pero con directivas leídas -> INFO de conformidad.
    if not hallazgos and cfg:
        hallazgos.append(Hallazgo(
            "H3-SSH", "H3-SSH-CONF-OK",
            "La configuración de sshd no presenta desviaciones de endurecimiento",
            Severidad.INFO, "informativo",
            f"{len(cfg)} directivas revisadas sin desviaciones", "", REFS))

    return hallazgos


# ------------------------------------------------- evaluación de la salida ssh-audit
def _h_algo(algo, sev, textos):
    """Hallazgo de un algoritmo SSH según la categoría de nota (fail/warn/info). La
    evidencia es el nombre del algoritmo + el texto genérico de la nota (sin secretos)."""
    nota = "; ".join(t for t in textos if t)
    if sev == Severidad.ALTA:
        titulo = f"Algoritmo SSH inseguro negociado por el servidor: {algo}"
        rec = ("Deshabilita este algoritmo en sshd_config; usa solo primitivas modernas "
               "(AES-GCM/ChaCha20, MAC *-etm con SHA-2, kex curve25519).")
    elif sev == Severidad.MEDIA:
        titulo = f"Algoritmo SSH desaconsejado negociado por el servidor: {algo}"
        rec = "Revisa y retira este algoritmo de sshd_config si tu parque de clientes lo permite."
    else:
        titulo = f"Nota informativa de ssh-audit sobre {algo}"
        rec = ""
    evid = f"{algo}: {nota}" if nota else algo
    return Hallazgo("H3-SSH", "H3-SSH-ALGO-" + algo.upper(), titulo,
                    sev, _estado(sev), _recorta(evid), rec, REFS)


def _evaluar_sshaudit(obj):
    """Convierte el JSON de `ssh-audit -j` en una lista de `Hallazgo`. Función PURA
    (no toca red ni procesos) y TOLERANTE a claves ausentes.

    Esquema (github.com/jtesta/ssh-audit): secciones de algoritmos `enc`/`mac`/`kex`/
    `key`, cada elemento {algorithm, notes:{fail?,warn?,info?: [str]}}; una lista
    `cves` (a menudo vacía desde 3.3.0) y un `banner` {software,raw,...}. Mapeo:
    nota fail -> ALTA (H3-SSH-ALGO-<ALGO>), warn -> MEDIA, info -> INFO; cualquier
    texto que aluda a un CVE/Terrapin/DHEat o la lista `cves` -> ALTA (H3-SSH-CVE).

    PRIVACIDAD: la sección `fingerprints` (huellas de host keys) se ignora a propósito.
    """
    if not isinstance(obj, dict):
        return []

    findings = []        # hallazgos de algoritmo (ALTA/MEDIA/INFO)
    cve_textos = []      # (algo|"", texto) que aluden a un CVE

    for seccion in ("enc", "mac", "kex", "key"):
        lista = obj.get(seccion)
        if not isinstance(lista, list):
            continue
        for item in lista:
            if not isinstance(item, dict):
                continue
            algo = str(item.get("algorithm") or "?")
            notes = item.get("notes")
            if not isinstance(notes, dict):
                continue
            buckets = {"fail": [], "warn": [], "info": []}
            for cat in ("fail", "warn", "info"):
                for texto in _lista_textos(notes.get(cat)):
                    if _menciona_cve(texto):
                        cve_textos.append((algo, texto))
                    else:
                        buckets[cat].append(texto)
            if buckets["fail"]:
                findings.append(_h_algo(algo, Severidad.ALTA, buckets["fail"]))
            if buckets["warn"]:
                findings.append(_h_algo(algo, Severidad.MEDIA, buckets["warn"]))
            if buckets["info"]:
                findings.append(_h_algo(algo, Severidad.INFO, buckets["info"]))

    # Lista `cves` (presente en versiones previas a 3.3.0; no fiable, solo si trae algo).
    cves = obj.get("cves")
    if isinstance(cves, list):
        for c in cves:
            nombre, desc = _cve_campos(c)
            if nombre or desc:
                cve_textos.append(("", (nombre + " " + desc).strip()))

    # additional_notes puede traer Terrapin/DHEat como texto suelto.
    for texto in _lista_textos(obj.get("additional_notes")):
        if _menciona_cve(texto):
            cve_textos.append(("", texto))

    # Hallazgos de CVE (ALTA), sin duplicados.
    cve_findings, vistos = [], set()
    for algo, texto in cve_textos:
        clave = (algo, texto)
        if clave in vistos:
            continue
        vistos.add(clave)
        evid = (f"{algo}: " if algo else "") + texto
        cve_findings.append(Hallazgo(
            "H3-SSH", "H3-SSH-CVE",
            "ssh-audit reporta una vulnerabilidad conocida en el servicio SSH",
            Severidad.ALTA, "confirmado", _recorta(evid),
            "Actualiza OpenSSH y deshabilita los algoritmos afectados (p. ej. Terrapin "
            "CVE-2023-48795: usa kex/MAC *-etm o chacha20; DHEat CVE-2002-20001: limita el rate de kex).",
            REFS))

    todas = cve_findings + findings

    # Tope de hallazgos: se conservan los de mayor severidad y se resume el resto.
    if len(todas) > MAX_ACTIVOS:
        todas.sort(key=lambda h: -int(h.severidad))
        extra = len(todas) - MAX_ACTIVOS
        todas = todas[:MAX_ACTIVOS]
        todas.append(Hallazgo(
            "H3-SSH", "H3-SSH-RESUMEN",
            "Se recortó la lista de hallazgos de ssh-audit",
            Severidad.INFO, "informativo",
            f"{extra} hallazgo(s) adicionales omitidos (se muestran los {MAX_ACTIVOS} de mayor severidad)",
            "Ejecuta 'ssh-audit' directamente contra el host para la lista completa.", REFS))

    # Banner/software para trazabilidad (público, no cuenta para el tope).
    banner = obj.get("banner")
    software = None
    if isinstance(banner, dict):
        software = banner.get("software") or banner.get("raw")
    if software:
        todas.insert(0, Hallazgo(
            "H3-SSH", "H3-SSH-BANNER", "Banner/software del servidor SSH detectado",
            Severidad.INFO, "informativo", _recorta(f"software={software}", 160), "", REFS))

    return todas


# ------------------------------------------------------------------------- módulo
class H3Ssh(Modulo):
    nombre = "H3-SSH"
    titulo = "Endurecimiento de SSH del host"
    activo = False          # HÍBRIDO: se ejecuta siempre y autogatea la parte activa con self.activos_ok
    etiqueta_escaneo = "ssh"
    descripcion = "Endurecimiento de SSH: sshd_config (pasivo) y ssh-audit contra el servicio (activo)"
    tipo = "hibrido"
    externa = SSH_AUDIT
    requiere_servidor = True

    # Constantes accesibles también como atributos del objeto.
    REFS = REFS
    MAX_ACTIVOS = MAX_ACTIVOS

    # ------------------------------------------------------------ pasivo (disco/SO)
    def _ruta_sshd(self, objetivo):
        """Ruta del sshd_config: la declarada en el objetivo o la del SO por defecto."""
        ruta = (objetivo.get("ssh") or {}).get("sshd_config")
        if ruta:
            return ruta
        return _RUTA_SSHD_NT if os.name == "nt" else _RUTA_SSHD_POSIX

    def _parsear_fichero(self, ruta, cfg):
        """Añade a `cfg` las directivas de un fichero sshd_config. Última aparición
        gana (override). Ignora comentarios y líneas vacías. Nunca lanza."""
        try:
            with open(ruta, "r", encoding="utf-8", errors="replace") as f:
                texto = f.read()
        except OSError:
            return
        for linea in texto.splitlines():
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            partes = linea.split(None, 1)
            if not partes:
                continue
            directiva = partes[0].lower()
            valor = partes[1].strip() if len(partes) > 1 else ""
            cfg[directiva] = valor

    def _leer_config(self, ruta):
        """Parsea el sshd_config y, best-effort, los '*.conf' de un 'sshd_config.d'
        adyacente. Devuelve el dict {directiva_minuscula: valor}."""
        cfg = {}
        self._parsear_fichero(ruta, cfg)
        dir_d = os.path.join(os.path.dirname(ruta), "sshd_config.d")
        if os.path.isdir(dir_d):
            try:
                ficheros = sorted(
                    os.path.join(dir_d, n) for n in os.listdir(dir_d)
                    if n.lower().endswith(".conf"))
            except OSError:
                ficheros = []
            for f in ficheros:
                self._parsear_fichero(f, cfg)
        return cfg

    def _pasivo(self, objetivo):
        """Parte pasiva: lee el sshd_config y lo evalúa. Si no existe, un único INFO."""
        ruta = self._ruta_sshd(objetivo)
        if not os.path.isfile(ruta):
            nota = ""
            if os.name == "nt":
                nota = " (OpenSSH Server probablemente no instalado)"
            return [Hallazgo(
                "H3-SSH", "H3-SSH-SIN-CONFIG",
                "No se encontró el fichero sshd_config del host",
                Severidad.INFO, "informativo",
                f"ruta probada: {ruta}" + nota,
                "Si el host sirve SSH, indica su sshd_config en ssh.sshd_config del objetivo; "
                "si no hay servidor SSH, no es un fallo.", REFS)]
        return _evaluar_sshd(self._leer_config(ruta))

    # ------------------------------------------------------------ activo (ssh-audit)
    def _host(self, objetivo):
        """Host a auditar: hostname del endpoint, si no el host del objetivo, si no loopback."""
        endpoint = objetivo.get("endpoint")
        if endpoint:
            import urllib.parse
            host = urllib.parse.urlparse(endpoint).hostname
            if host:
                return host
        return objetivo.get("host", "127.0.0.1")

    def _timeout(self, objetivo):
        try:
            return objetivo["herramientas"]["ssh-audit"]["timeout"]
        except (KeyError, TypeError):
            return 30

    def _activo(self, objetivo, host, puerto_ssh):
        """Parte activa: detecta ssh-audit y, si está, lo ejecuta contra host:puerto y
        normaliza su JSON. Si no está instalada, un único INFO con cómo instalarla."""
        det = herramientas.detectar(
            SSH_AUDIT, objetivo.get("herramientas", {}))
        if not det.disponible:
            return [Hallazgo(
                "H3-SSH", "H3-SSH-NO-AUDIT", "ssh-audit no está instalada",
                Severidad.INFO, "informativo", det.error or "",
                "Instálala para el análisis activo de SSH: pip install ssh-audit", REFS)]

        res = herramientas.ejecutar(
            [det.ruta, "-j", "--skip-rate-test", "-n", "-p", str(puerto_ssh), host],
            timeout=self._timeout(objetivo))

        salida = [Hallazgo(
            "H3-SSH", "H3-SSH-AUDIT", "ssh-audit ejecutada",
            Severidad.INFO, "informativo", f"version={det.version or 'desconocida'}", "", REFS)]

        obj = None
        if res.stdout and res.stdout.strip():
            try:
                obj = json.loads(res.stdout)
            except (ValueError, TypeError):
                obj = None
        if obj is None:
            detalle = "expiró el tiempo límite" if res.expiro else (
                res.error or f"returncode={res.returncode}; salida no interpretable como JSON")
            salida.append(Hallazgo(
                "H3-SSH", "H3-SSH-ERROR",
                "ssh-audit no devolvió una salida JSON interpretable",
                Severidad.INFO, "informativo", _recorta(str(detalle), 160),
                "Comprueba que el servicio SSH responde en ese host/puerto y repite el análisis.", REFS))
            return salida

        salida.extend(_evaluar_sshaudit(obj))
        return salida

    # --------------------------------------------------------------- orquestación
    def ejecutar(self, objetivo):
        host = self._host(objetivo)
        puerto_ssh = (objetivo.get("ssh") or {}).get("puerto", 22)
        local = red.es_host_local(host)
        # El sshd_config de este equipo no dice nada de otro host.
        hallazgos = list(self._pasivo(objetivo)) if local else [Hallazgo(
            "H3-SSH", "H3-SSH-NO-LOCAL", "No se ha revisado el sshd_config del host",
            Severidad.INFO, "informativo", "el host auditado no es este equipo: su sshd_config no está aquí",
            "Ejecuta MRRobotIA en ese host para revisar su configuración de SSH.", REFS)]

        # ---- GATING ACTIVO -----------------------------------------------------
        omision = self.motivo_omision_activa(objetivo, local)
        if omision:
            hallazgos.append(Hallazgo(
                "H3-SSH", "H3-SSH-ACTIVO-OMITIDO", "Análisis activo de SSH omitido",
                Severidad.INFO, "informativo", omision,
                "El análisis con ssh-audit exige --permitir-activos y permitir_activos=true y, en un host no local, "
                "autorizacion.confirmo_no_local=true con permiso escrito.", REFS))
            return [h for h in hallazgos if h is not None]

        # ---- ACTIVO (solo si autorizado y host permitido) ----------------------
        try:
            hallazgos.extend(self._activo(objetivo, host, puerto_ssh))
        except Exception as e:
            hallazgos.append(Hallazgo(
                "H3-SSH", "H3-SSH-ERROR", "Error durante el análisis activo de SSH",
                Severidad.INFO, "informativo", type(e).__name__,
                "Revisa la configuración de 'ssh' en el objetivo y el estado del servicio SSH.", REFS))

        return [h for h in hallazgos if h is not None]
