"""Pruebas de H3-SSH: endurecimiento de SSH del host.

Prueban las funciones PURAS (`_evaluar_sshd`, `_evaluar_sshaudit`) con entradas
fabricadas —sin servidor SSH ni `ssh-audit` instalado— y una integración ligera de
`ejecutar()` en modo pasivo (sshd_config temporal). Verifican además el invariante de
privacidad: la evidencia nunca contiene claves privadas, host keys ni sus huellas.
"""
from mrrobot.modulos import h3_ssh as h3
from mrrobot.modulos.h3_ssh import H3Ssh, _evaluar_sshd, _evaluar_sshaudit
from mrrobot.nucleo import Severidad


# ----------------------------------------------------- _evaluar_sshd (parte pasiva)
def test_sshd_permitrootlogin_yes_es_alta():
    hallazgos = _evaluar_sshd({"permitrootlogin": "yes"})
    por_id = {h.id: h for h in hallazgos}
    assert "H3-SSH-CONF-PERMITROOTLOGIN" in por_id
    assert por_id["H3-SSH-CONF-PERMITROOTLOGIN"].severidad == Severidad.ALTA


def test_sshd_permitrootlogin_prohibit_password_es_media():
    h = {x.id: x for x in _evaluar_sshd({"permitrootlogin": "prohibit-password"})}
    assert h["H3-SSH-CONF-PERMITROOTLOGIN"].severidad == Severidad.MEDIA


def test_sshd_permitemptypasswords_yes_es_critica():
    h = {x.id: x for x in _evaluar_sshd({"permitemptypasswords": "yes"})}
    assert "H3-SSH-CONF-PERMITEMPTYPASSWORDS" in h
    assert h["H3-SSH-CONF-PERMITEMPTYPASSWORDS"].severidad == Severidad.CRITICA


def test_sshd_ciphers_cbc_es_alta():
    hallazgos = _evaluar_sshd({"ciphers": "aes128-cbc,aes256-gcm@openssh.com"})
    por_id = {h.id: h for h in hallazgos}
    assert "H3-SSH-CONF-CIPHERS" in por_id
    assert por_id["H3-SSH-CONF-CIPHERS"].severidad == Severidad.ALTA
    # La evidencia es la política (el valor de la directiva), no un secreto.
    assert "aes128-cbc" in por_id["H3-SSH-CONF-CIPHERS"].evidencia


def test_sshd_macs_y_kex_y_protocolo():
    assert {x.id: x for x in _evaluar_sshd({"macs": "hmac-md5,hmac-sha2-256"})}[
        "H3-SSH-CONF-MACS"].severidad == Severidad.ALTA
    assert {x.id: x for x in _evaluar_sshd({"kexalgorithms": "diffie-hellman-group1-sha1"})}[
        "H3-SSH-CONF-KEXALGORITHMS"].severidad == Severidad.ALTA
    assert {x.id: x for x in _evaluar_sshd({"protocol": "2,1"})}[
        "H3-SSH-CONF-PROTOCOL"].severidad == Severidad.CRITICA


def test_sshd_config_segura_sin_desviaciones_altas():
    """Config razonable: no debe haber ninguna severidad MEDIA o superior (puede haber
    BAJA por LoginGraceTime/lista blanca ausentes, o el INFO de conformidad)."""
    hallazgos = _evaluar_sshd({
        "permitrootlogin": "no",
        "passwordauthentication": "no",
        "pubkeyauthentication": "yes",
        "maxauthtries": "3",
    })
    assert all(h.severidad < Severidad.MEDIA for h in hallazgos)
    # Y, desde luego, ninguna desviación de PermitRootLogin ni de autenticación.
    ids = {h.id for h in hallazgos}
    assert "H3-SSH-CONF-PERMITROOTLOGIN" not in ids
    assert "H3-SSH-CONF-PASSWORDAUTHENTICATION" not in ids


def test_sshd_todo_correcto_devuelve_conf_ok():
    """Config que cubre también los avisos BAJA (lista blanca, grace time) -> INFO OK."""
    hallazgos = _evaluar_sshd({
        "permitrootlogin": "no",
        "maxauthtries": "4",
        "logingracetime": "30",
        "allowusers": "sergio",
    })
    assert len(hallazgos) == 1
    assert hallazgos[0].id == "H3-SSH-CONF-OK"
    assert hallazgos[0].severidad == Severidad.INFO


def test_sshd_maxauthtries_y_logingracetime_ausentes_son_baja():
    hallazgos = _evaluar_sshd({"permitrootlogin": "no", "allowusers": "x"})
    por_id = {h.id: h for h in hallazgos}
    assert por_id["H3-SSH-CONF-MAXAUTHTRIES"].severidad == Severidad.BAJA
    assert por_id["H3-SSH-CONF-LOGINGRACETIME"].severidad == Severidad.BAJA


# ---------------------------------------------- _evaluar_sshaudit (parte activa)
def test_sshaudit_nota_fail_en_cifrado_es_alta_sin_secretos():
    obj = {"enc": [{"algorithm": "aes128-cbc",
                    "notes": {"fail": ["using weak cipher mode"]}}]}
    hallazgos = _evaluar_sshaudit(obj)
    altas = [h for h in hallazgos if h.severidad == Severidad.ALTA]
    assert altas, "debe haber al menos un hallazgo ALTA"
    h = altas[0]
    assert h.id == "H3-SSH-ALGO-AES128-CBC"
    assert "aes128-cbc" in h.evidencia
    # Invariante de privacidad: nunca una clave ni host key en la evidencia.
    volcado = " ".join(f"{x.evidencia} {x.recomendacion}" for x in hallazgos)
    for secreto in ("BEGIN", "PRIVATE KEY", "ssh-rsa AAAA", "SHA256:"):
        assert secreto not in volcado


def test_sshaudit_warn_es_media_e_info_es_info():
    obj = {"mac": [
        {"algorithm": "hmac-sha1", "notes": {"warn": ["usando sha1"]}},
        {"algorithm": "umac-128-etm@openssh.com", "notes": {"info": ["disponible desde OpenSSH 6.2"]}},
    ]}
    por_sev = {h.severidad for h in _evaluar_sshaudit(obj)}
    assert Severidad.MEDIA in por_sev
    assert Severidad.INFO in por_sev


def test_sshaudit_cve_terrapin_es_alta_y_id_cve():
    # El texto de la nota alude a Terrapin (CVE-2023-48795) -> H3-SSH-CVE (ALTA).
    obj = {"kex": [{"algorithm": "chacha20-poly1305@openssh.com",
                    "notes": {"warn": ["vulnerable to the Terrapin attack (CVE-2023-48795)"]}}]}
    por_id = {h.id: h for h in _evaluar_sshaudit(obj)}
    assert "H3-SSH-CVE" in por_id
    assert por_id["H3-SSH-CVE"].severidad == Severidad.ALTA
    # La nota con CVE no se duplica además como H3-SSH-ALGO-*.
    assert "H3-SSH-ALGO-CHACHA20-POLY1305@OPENSSH.COM" not in por_id


def test_sshaudit_ignora_fingerprints_y_banner_es_trazabilidad():
    obj = {
        "banner": {"software": "OpenSSH_9.6", "raw": "SSH-2.0-OpenSSH_9.6"},
        "fingerprints": [{"hash": "SHA256:deadbeefHUELLAFALSA", "hashtype": "sha256",
                          "keytype": "ssh-ed25519", "fpr": "ssh-ed25519 AAAAFAKEKEY"}],
        "enc": [{"algorithm": "aes256-gcm@openssh.com", "notes": {}}],
    }
    hallazgos = _evaluar_sshaudit(obj)
    por_id = {h.id: h for h in hallazgos}
    assert por_id["H3-SSH-BANNER"].severidad == Severidad.INFO
    assert "OpenSSH_9.6" in por_id["H3-SSH-BANNER"].evidencia
    # Ni la huella ni la clave falsa aparecen en NINGUNA evidencia.
    volcado = " ".join(h.evidencia for h in hallazgos)
    assert "deadbeefHUELLAFALSA" not in volcado
    assert "AAAAFAKEKEY" not in volcado


def test_sshaudit_tolerante_a_entradas_raras():
    assert _evaluar_sshaudit(None) == []
    assert _evaluar_sshaudit({}) == []
    assert _evaluar_sshaudit({"enc": "no-es-lista"}) == []


def test_sshaudit_recorta_a_veinte():
    enc = [{"algorithm": f"algo-malo-{i}", "notes": {"fail": ["débil"]}} for i in range(30)]
    hallazgos = _evaluar_sshaudit({"enc": enc})
    assert any(h.id == "H3-SSH-RESUMEN" for h in hallazgos)
    # Como mucho el tope de algoritmos + el resumen (el banner no está presente aquí).
    assert len([h for h in hallazgos if h.id != "H3-SSH-RESUMEN"]) <= h3.MAX_ACTIVOS


# -------------------------------------------- integración ligera de ejecutar()
def test_ejecutar_pasivo_lee_config_y_omite_activo(tmp_path):
    """Con un sshd_config real en disco y sin --permitir-activos: evalúa la config y
    marca el análisis activo como omitido (no intenta ejecutar ssh-audit)."""
    cfg = tmp_path / "sshd_config"
    cfg.write_text("# comentario\nPermitRootLogin yes\nPasswordAuthentication yes\n",
                   encoding="utf-8")
    m = H3Ssh()
    m.activos_ok = False
    objetivo = {"host": "127.0.0.1", "autorizacion": {},
                "ssh": {"sshd_config": str(cfg)}}
    hallazgos = m.ejecutar(objetivo)
    ids = {h.id for h in hallazgos}
    assert "H3-SSH-CONF-PERMITROOTLOGIN" in ids
    assert "H3-SSH-ACTIVO-OMITIDO" in ids
    # No se intentó nada activo (ni ssh-audit ni su traza de versión).
    assert ids.isdisjoint({"H3-SSH-AUDIT", "H3-SSH-NO-AUDIT"})


def test_ejecutar_sin_config_es_info(tmp_path):
    m = H3Ssh()
    m.activos_ok = False
    objetivo = {"host": "127.0.0.1", "autorizacion": {},
                "ssh": {"sshd_config": str(tmp_path / "no_existe")}}
    ids = {h.id for h in m.ejecutar(objetivo)}
    assert "H3-SSH-SIN-CONFIG" in ids


def test_ejecutar_host_no_local_sin_confirmacion_omite_activo():
    m = H3Ssh()
    m.activos_ok = True  # aunque los activos estén habilitados...
    objetivo = {"host": "10.0.0.5", "autorizacion": {"confirmo_no_local": False},
                "ssh": {"sshd_config": "ruta/que/no/existe"}}
    hallazgos = m.ejecutar(objetivo)
    omitidos = [h for h in hallazgos if h.id == "H3-SSH-ACTIVO-OMITIDO"]
    assert omitidos and "no local" in omitidos[0].evidencia
