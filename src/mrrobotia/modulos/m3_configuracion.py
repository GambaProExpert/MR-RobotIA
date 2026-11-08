"""
M3 — Auditoría de configuración (postura en reposo y de red del despliegue).

Módulo PASIVO y de SOLO LECTURA: a partir de las rutas declaradas en el objetivo
(`usuarios`, `auditoria`/`dir_logs` y, opcionalmente, `app_dir`), revisa que la
configuración no exponga información sensible ni credenciales. No abre puertos ni
interactúa con el servicio: solo lee ficheros de configuración. **Nunca imprime
secretos**: no vuelca contraseñas ni hashes y solo informa con recuentos y nombres
de campo; si cita un usuario, lo hace de forma mínima.

Comprueba:
  1. usuarios.json — PBKDF2 (iteraciones, sal, hash), ausencia de contraseñas en
     claro y permisos del fichero.
  2. Registro de auditoría — que NO guarde el TEXTO de las preguntas (solo su hash),
     rotación por tamaño y permisos.
  3. TLS y enlace de red — `.streamlit/config.toml` (server.address, sslCertFile/
     sslKeyFile) o, si no existe, recordatorio de que el enlace a 127.0.0.1 y el TLS
     dependen del arranque.

Atacantes del modelo de amenazas: A3 (interno con acceso a disco) y A5 (exposición
del servicio en red). Marcos: OWASP LLM02 (fuga de información sensible), NIST AI
600-1 (2.4 Data Privacy, 2.9 Information Security); para la parte de red, además
OWASP LLM10 y MITRE ATLAS AML.T0049.
"""
from __future__ import annotations

import json
import os
import string
import unicodedata
from pathlib import Path

from mrrobotia.nucleo import Modulo, Hallazgo, Severidad

REFS = {"owasp": "LLM02", "nist": "2.4, 2.9"}
REFS_RED = {"owasp": "LLM10", "atlas": "AML.T0049", "nist": "2.9"}

ITERACIONES_MIN = 100_000
SAL_MIN_BYTES = 16
MAX_LOG_BYTES = 50 * 1024 * 1024
_MAX_LINEA = 1_000_000          # no intentes parsear líneas anómalas (defensa de memoria)

# Claves que delatarían una contraseña almacenada en claro en usuarios.json.
_PASS_SUBSTR = ("password", "passwd", "contrasena", "clave", "pwd")
_PASS_EXACT = {"pass"}
# Claves que NO deberían llevar el TEXTO de una pregunta en la auditoría: debe
# guardarse solo su hash (p. ej. en 'pregunta_sha256', que no está en esta lista).
_TEXTO_CLAVES = {"pregunta", "texto", "prompt", "input", "mensaje", "consulta", "query"}
_HEX = set(string.hexdigits)
_LONGITUDES_HASH = {16, 32, 40, 56, 64, 96, 128}


def _normaliza(clave):
    """Minúsculas y sin acentos (contraseña -> contrasena) para comparar nombres de campo."""
    base = unicodedata.normalize("NFKD", str(clave))
    return "".join(c for c in base if not unicodedata.combining(c)).lower()


def _es_clave_pass(clave):
    cn = _normaliza(clave)
    return cn in _PASS_EXACT or any(t in cn for t in _PASS_SUBSTR)


def _parece_hash(valor):
    v = valor.strip()
    return len(v) in _LONGITUDES_HASH and all(c in _HEX for c in v)


def _sal_bytes(sal):
    """Longitud en bytes de una sal guardada como hex (o como texto, si no lo es)."""
    s = sal.strip()
    if s and len(s) % 2 == 0 and all(c in _HEX for c in s):
        return len(s) // 2
    return len(s.encode("utf-8"))


def _hallazgos_permisos(ruta, idbase, etiqueta):
    """Permisos del fichero: ALTA en POSIX si es legible por grupo/otros; INFO en Windows."""
    if os.name == "nt":
        return [Hallazgo(
            "M3", f"M3-{idbase}-PERMISOS", f"Permisos de {etiqueta}: revisar las ACL NTFS a mano",
            Severidad.INFO, "informativo", str(ruta),
            "En Windows os.stat no expone los bits POSIX de forma fiable. Comprueba con 'icacls' "
            "que solo el propietario (y Administradores) puedan leer el fichero (A3).", REFS)]
    modo = ruta.stat().st_mode & 0o777
    if modo & 0o044:
        return [Hallazgo(
            "M3", f"M3-{idbase}-PERMISOS", f"{etiqueta} es legible por grupo u otros",
            Severidad.ALTA, "confirmado", f"modo {oct(modo)}",
            "Restringe el acceso al propietario (chmod 600). Un interno con acceso a disco podría "
            "leer credenciales o la auditoría (A3).", REFS)]
    return []


def _leer_toml(ruta):
    try:
        import tomllib
        with open(ruta, "rb") as f:
            return tomllib.load(f)
    except ModuleNotFoundError:
        return _toml_minimo(ruta)        # Python < 3.11 sin tomllib
    except Exception:
        return {}


def _toml_minimo(ruta):
    """Lector TOML mínimo (solo tablas y pares clave = \"valor\") para entornos sin tomllib."""
    datos, seccion = {}, None
    try:
        for linea in ruta.read_text(encoding="utf-8").splitlines():
            t = linea.split("#", 1)[0].strip()
            if not t:
                continue
            if t.startswith("[") and t.endswith("]"):
                seccion = t[1:-1].strip()
                datos.setdefault(seccion, {})
            elif "=" in t and seccion is not None:
                k, v = t.split("=", 1)
                datos[seccion][k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        return {}
    return datos


def _hay_rotacion(ruta):
    """¿Hay ficheros hermanos que sugieran rotación del log (auditoria.jsonl.1, .gz, con fecha)?"""
    try:
        for otro in ruta.parent.iterdir():
            if otro.is_file() and otro.name != ruta.name and otro.name.startswith(ruta.stem):
                return True
    except OSError:
        pass
    return False


class M3Configuracion(Modulo):
    nombre = "M3"
    titulo = "Auditoría de configuración (credenciales, auditoría, TLS/red)"
    activo = False
    etiqueta_escaneo = "config"

    def ejecutar(self, objetivo):
        tiene_usuarios = bool(objetivo.get("usuarios"))
        tiene_audit = bool(objetivo.get("auditoria") or objetivo.get("dir_logs"))
        tiene_app = bool(objetivo.get("app_dir"))
        if not (tiene_usuarios or tiene_audit or tiene_app):
            return [Hallazgo(
                "M3", "M3-SIN-RUTAS", "No se declararon rutas de configuración para auditar",
                Severidad.INFO, "informativo", "",
                "Añade al objetivo las claves 'usuarios', 'auditoria' o 'dir_logs' y, opcionalmente, "
                "'app_dir' (para .streamlit/config.toml).", REFS)]
        h = []
        if tiene_usuarios:
            h += self._revisar_usuarios(objetivo["usuarios"])
        if tiene_audit:
            h += self._revisar_auditoria(objetivo)
        h += self._revisar_red(objetivo)
        return h

    # ------------------------------------------------------------------ usuarios
    def _revisar_usuarios(self, ruta_str):
        ruta = Path(ruta_str)
        if not ruta.exists():
            return [Hallazgo(
                "M3", "M3-USUARIOS-FALTA", "No existe el fichero de usuarios declarado",
                Severidad.INFO, "informativo", str(ruta),
                "Declara la ruta correcta en 'usuarios' si este objetivo tiene login.", REFS)]
        h = list(_hallazgos_permisos(ruta, "USUARIOS", "usuarios.json"))
        try:
            datos = json.loads(ruta.read_text(encoding="utf-8"))
        except Exception as e:
            h.append(Hallazgo(
                "M3", "M3-USUARIOS-ILEGIBLE", "No se puede leer usuarios.json como JSON",
                Severidad.ALTA, "confirmado", type(e).__name__,
                "Revisa el formato del fichero de usuarios.", REFS))
            return h
        if not isinstance(datos, dict):
            h.append(Hallazgo(
                "M3", "M3-USUARIOS-FORMATO", "usuarios.json no es un objeto de usuarios",
                Severidad.MEDIA, "confirmado", f"tipo {type(datos).__name__}",
                "Se esperaba un objeto {usuario: {rol, sal, iteraciones, hash, ...}}.", REFS))
            return h

        n = iter_debil = sal_debil = hash_falta = pass_usuarios = 0
        campos_pass = set()
        for info in datos.values():
            if not isinstance(info, dict):
                continue
            n += 1
            it = info.get("iteraciones")
            if not isinstance(it, int) or it < ITERACIONES_MIN:
                iter_debil += 1
            sal = info.get("sal")
            if not isinstance(sal, str) or not sal.strip() or _sal_bytes(sal) < SAL_MIN_BYTES:
                sal_debil += 1
            if not info.get("hash"):
                hash_falta += 1
            sosp = [str(c) for c in info if _es_clave_pass(c)]
            if sosp:
                pass_usuarios += 1
                campos_pass.update(sosp)

        if campos_pass:
            h.append(Hallazgo(
                "M3", "M3-USUARIOS-PASS-CLARO", "Posible contraseña almacenada en claro en usuarios.json",
                Severidad.CRITICA, "confirmado",
                f"{pass_usuarios} usuario(s); campos: {', '.join(sorted(campos_pass))}",
                "Nunca almacenes contraseñas: guarda solo el hash PBKDF2 con su sal. Elimina ese campo "
                "y rota las credenciales afectadas.", REFS))
        if iter_debil:
            h.append(Hallazgo(
                "M3", "M3-USUARIOS-ITER-DEBIL", "Iteraciones de PBKDF2 ausentes o insuficientes",
                Severidad.ALTA, "confirmado",
                f"{iter_debil} de {n} usuario(s) con iteraciones ausentes o < {ITERACIONES_MIN}",
                f"Usa al menos {ITERACIONES_MIN} iteraciones (el Caso 1 usa 200000) y vuelve a derivar los hashes.",
                REFS))
        if hash_falta:
            h.append(Hallazgo(
                "M3", "M3-USUARIOS-HASH-FALTA", "Usuarios sin hash de contraseña",
                Severidad.ALTA, "confirmado", f"{hash_falta} de {n} usuario(s) sin campo 'hash'",
                "Cada usuario debe tener su hash PBKDF2; sin él no hay autenticación verificable.", REFS))
        if sal_debil:
            h.append(Hallazgo(
                "M3", "M3-USUARIOS-SAL-DEBIL", "Sal ausente o demasiado corta",
                Severidad.MEDIA, "confirmado",
                f"{sal_debil} de {n} usuario(s) sin sal o con sal < {SAL_MIN_BYTES} bytes",
                f"Usa una sal aleatoria de al menos {SAL_MIN_BYTES} bytes por usuario.", REFS))
        if n and not (campos_pass or iter_debil or hash_falta or sal_debil):
            h.append(Hallazgo(
                "M3", "M3-USUARIOS-OK", "Credenciales con PBKDF2 correcto",
                Severidad.INFO, "informativo",
                f"{n} usuario(s); iteraciones >= {ITERACIONES_MIN}, sal y hash presentes"))
        elif n == 0:
            h.append(Hallazgo(
                "M3", "M3-USUARIOS-VACIO", "usuarios.json no contiene usuarios",
                Severidad.INFO, "informativo", str(ruta)))
        return h

    # ----------------------------------------------------------------- auditoría
    def _revisar_auditoria(self, objetivo):
        if objetivo.get("auditoria"):
            ruta = Path(objetivo["auditoria"])
        else:
            ruta = Path(objetivo["dir_logs"]) / "auditoria.jsonl"
        if not ruta.exists():
            return [Hallazgo(
                "M3", "M3-AUDIT-FALTA", "No existe el registro de auditoría declarado",
                Severidad.INFO, "informativo", str(ruta),
                "Declara la ruta correcta ('auditoria' o 'dir_logs') si este objetivo registra auditoría.",
                REFS)]
        h = list(_hallazgos_permisos(ruta, "AUDIT", "auditoria.jsonl"))
        entradas = con_texto = 0
        campos = set()
        try:
            with open(ruta, "r", encoding="utf-8", errors="replace") as f:
                for linea in f:
                    if len(linea) > _MAX_LINEA:
                        continue
                    linea = linea.strip()
                    if not linea:
                        continue
                    try:
                        d = json.loads(linea)
                    except Exception:
                        continue
                    if not isinstance(d, dict):
                        continue
                    entradas += 1
                    sosp = [str(k) for k, v in d.items()
                            if str(k).lower() in _TEXTO_CLAVES and isinstance(v, str)
                            and v.strip() and not _parece_hash(v)]
                    if sosp:
                        con_texto += 1
                        campos.update(sosp)
        except OSError as e:
            h.append(Hallazgo(
                "M3", "M3-AUDIT-ILEGIBLE", "No se puede leer el registro de auditoría",
                Severidad.MEDIA, "confirmado", type(e).__name__,
                "Revisa permisos y codificación del fichero de auditoría.", REFS))
            return h

        if con_texto:
            # Evidencia: solo el recuento y los NOMBRES de campo; nunca el texto de la pregunta.
            h.append(Hallazgo(
                "M3", "M3-AUDIT-TEXTO-PREGUNTA", "La auditoría guarda el TEXTO de las preguntas",
                Severidad.ALTA, "confirmado",
                f"{con_texto} entrada(s) con texto en campos: {', '.join(sorted(campos))} "
                "(debe guardarse solo el hash)",
                "Registra solo el hash de la pregunta (p. ej. 'pregunta_sha256'), nunca su texto: en claro "
                "es información sensible accesible con acceso a disco (A3).", REFS))
        tam = ruta.stat().st_size
        if tam > MAX_LOG_BYTES and not _hay_rotacion(ruta):
            h.append(Hallazgo(
                "M3", "M3-AUDIT-ROTACION", "El registro de auditoría es grande y no parece rotarse",
                Severidad.BAJA, "confirmado", f"{tam // (1024 * 1024)} MB sin ficheros rotados junto a él",
                "Configura rotación de logs (por tamaño o fecha) y considera una copia con integridad.", REFS))
        if entradas and not con_texto:
            h.append(Hallazgo(
                "M3", "M3-AUDIT-OK", "La auditoría no contiene el texto de las preguntas",
                Severidad.INFO, "informativo",
                f"{entradas} entrada(s) revisadas; solo el hash de la pregunta"))
        elif entradas == 0:
            h.append(Hallazgo(
                "M3", "M3-AUDIT-VACIO", "El registro de auditoría no tiene entradas legibles",
                Severidad.INFO, "informativo", str(ruta)))
        return h

    # --------------------------------------------------------------------- red/TLS
    def _revisar_red(self, objetivo):
        app_dir = objetivo.get("app_dir")
        config_toml = Path(app_dir) / ".streamlit" / "config.toml" if app_dir else None
        if not config_toml or not config_toml.exists():
            detalle = str(config_toml) if config_toml else "no se declaró 'app_dir'"
            return [Hallazgo(
                "M3", "M3-RED-SIN-CONFIG", "El enlace de red y el TLS dependen del arranque, no del código",
                Severidad.INFO, "informativo", detalle,
                "La app enlaza a 127.0.0.1 solo si se arranca con '--server.address 127.0.0.1' y no usa "
                "TLS salvo que se configure. Revisa el arranque o añade .streamlit/config.toml con "
                "server.address y sslCertFile/sslKeyFile (A5).", REFS_RED)]

        cfg = _leer_toml(config_toml)
        servidor = cfg.get("server", {}) if isinstance(cfg, dict) else {}
        h = []
        address = servidor.get("address")
        if address is None:
            h.append(Hallazgo(
                "M3", "M3-RED-BIND-AUSENTE", "config.toml no fija server.address",
                Severidad.INFO, "informativo", str(config_toml),
                'Añade server.address = "127.0.0.1" para no depender del parámetro de arranque (A5).',
                REFS_RED))
        elif str(address) in ("0.0.0.0", "::", ""):
            h.append(Hallazgo(
                "M3", "M3-RED-BIND-EXPUESTO", "La app se enlaza a todas las interfaces de red",
                Severidad.ALTA, "confirmado", f"server.address = {address!r}",
                "Enlaza solo a 127.0.0.1. Con 0.0.0.0 el servicio queda accesible desde la red, sin "
                "límite de login por IP ni TLS (A5).", REFS_RED))
        elif str(address) in ("127.0.0.1", "localhost", "::1"):
            h.append(Hallazgo(
                "M3", "M3-RED-BIND-LOCAL", "La app se enlaza solo a localhost",
                Severidad.INFO, "informativo", f"server.address = {address!r}"))
        else:
            h.append(Hallazgo(
                "M3", "M3-RED-BIND-NO-LOCAL", "La app se enlaza a una dirección no local",
                Severidad.MEDIA, "confirmado", f"server.address = {address!r}",
                "Confirma que esa interfaz es deliberada y está protegida; prefiere 127.0.0.1 (A5).",
                REFS_RED))

        if servidor.get("sslCertFile") and servidor.get("sslKeyFile"):
            h.append(Hallazgo(
                "M3", "M3-TLS-OK", "TLS configurado en Streamlit",
                Severidad.INFO, "informativo", "sslCertFile y sslKeyFile definidos"))
        else:
            h.append(Hallazgo(
                "M3", "M3-TLS-SIN-CERT", "Streamlit sin TLS",
                Severidad.MEDIA, "confirmado", "no hay sslCertFile/sslKeyFile en config.toml",
                "Sin TLS el tráfico va en claro; aceptable solo en bucle local. Si se expone en red, "
                "configura sslCertFile/sslKeyFile o pon un proxy inverso con TLS (A5).", REFS_RED))
        return h
