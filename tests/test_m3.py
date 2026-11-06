"""Pruebas de M3: auditoría de configuración (usuarios.json, auditoría, TLS/red).

Usa tmp_path y fixtures sintéticas: NO toca datos reales. En Windows no afirma los
bits POSIX (os.stat no los da de forma fiable); hay una prueba por plataforma.
"""
import json
import os

import pytest

from mrrobot.modulos.m3_configuracion import M3Configuracion
from mrrobot.nucleo import Severidad


def _por_id(hallazgos):
    return {h.id: h for h in hallazgos}


def _blindar(ruta):
    """En POSIX deja el fichero solo para el propietario (no dispara el hallazgo de permisos)."""
    if os.name != "nt":
        os.chmod(ruta, 0o600)


def test_m3_usuarios_debiles_y_auditoria_con_texto(tmp_path):
    usuarios = tmp_path / "usuarios.json"
    usuarios.write_text(json.dumps({
        "alice": {"rol": "ingeniero", "iteraciones": 1000, "hash": "ab" * 32},   # sin sal, iter bajas
        "bob": {"rol": "mantenimiento", "iteraciones": 200000, "sal": "00" * 16,
                "hash": "cd" * 32, "password": "hunter2"},                        # contraseña en claro
    }), encoding="utf-8")
    _blindar(usuarios)

    auditoria = tmp_path / "auditoria.jsonl"
    auditoria.write_text(
        json.dumps({"fecha": "2026-11-06T10:00:00", "evento": "consulta", "usuario": "bob",
                    "pregunta": "¿cuál es el MTOW de la WV003?"}) + "\n"
        + json.dumps({"fecha": "2026-11-06T10:01:00", "evento": "consulta", "usuario": "bob",
                      "pregunta_sha256": "deadbeefdeadbeef"}) + "\n",
        encoding="utf-8")
    _blindar(auditoria)

    h = M3Configuracion().ejecutar({"usuarios": str(usuarios), "auditoria": str(auditoria)})
    por_id = _por_id(h)

    assert por_id["M3-USUARIOS-ITER-DEBIL"].severidad == Severidad.ALTA
    assert por_id["M3-USUARIOS-SAL-DEBIL"].severidad == Severidad.MEDIA
    assert por_id["M3-USUARIOS-PASS-CLARO"].severidad == Severidad.CRITICA
    assert por_id["M3-AUDIT-TEXTO-PREGUNTA"].severidad == Severidad.ALTA

    # El informe NUNCA debe contener el texto de la pregunta ni la contraseña en claro.
    volcado = " ".join(f"{x.titulo} {x.evidencia} {x.recomendacion}" for x in h)
    assert "MTOW" not in volcado
    assert "WV003" not in volcado
    assert "hunter2" not in volcado


def test_m3_configuracion_limpia_sin_hallazgos_relevantes(tmp_path):
    usuarios = tmp_path / "usuarios.json"
    usuarios.write_text(json.dumps({
        "alice": {"rol": "ingeniero", "sal": "ab" * 16, "iteraciones": 200000,
                  "hash": "cd" * 32, "creado": "2026-11-06T10:00:00"},
    }), encoding="utf-8")
    _blindar(usuarios)

    auditoria = tmp_path / "auditoria.jsonl"
    auditoria.write_text(
        json.dumps({"fecha": "2026-11-06T10:00:00", "evento": "consulta", "usuario": "alice",
                    "rol": "ingeniero", "pregunta_sha256": "deadbeefdeadbeef",
                    "longitud_pregunta": 23}) + "\n",
        encoding="utf-8")
    _blindar(auditoria)

    h = M3Configuracion().ejecutar({"usuarios": str(usuarios), "auditoria": str(auditoria)})

    relevantes = [(x.id, x.severidad.name) for x in h if x.severidad >= Severidad.MEDIA]
    assert relevantes == [], relevantes
    por_id = _por_id(h)
    assert por_id["M3-USUARIOS-OK"].severidad == Severidad.INFO
    assert por_id["M3-AUDIT-OK"].severidad == Severidad.INFO


def test_m3_rutas_inexistentes_son_informativas(tmp_path):
    objetivo = {"usuarios": str(tmp_path / "no_existe.json"),
                "auditoria": str(tmp_path / "tampoco.jsonl")}
    por_id = _por_id(M3Configuracion().ejecutar(objetivo))
    assert por_id["M3-USUARIOS-FALTA"].severidad == Severidad.INFO
    assert por_id["M3-AUDIT-FALTA"].severidad == Severidad.INFO


def test_m3_dir_logs_resuelve_auditoria(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "auditoria.jsonl").write_text(
        json.dumps({"evento": "login_ok", "pregunta_sha256": "aa" * 8}) + "\n", encoding="utf-8")
    _blindar(logs / "auditoria.jsonl")
    por_id = _por_id(M3Configuracion().ejecutar({"dir_logs": str(logs)}))
    assert por_id["M3-AUDIT-OK"].severidad == Severidad.INFO


def test_m3_red_bind_expuesto_y_sin_tls(tmp_path):
    app = tmp_path / "app"
    (app / ".streamlit").mkdir(parents=True)
    (app / ".streamlit" / "config.toml").write_text(
        '[server]\naddress = "0.0.0.0"\nport = 8501\n', encoding="utf-8")
    por_id = _por_id(M3Configuracion().ejecutar({"app_dir": str(app)}))
    assert por_id["M3-RED-BIND-EXPUESTO"].severidad == Severidad.ALTA
    assert por_id["M3-TLS-SIN-CERT"].severidad == Severidad.MEDIA


def test_m3_red_bind_local_con_tls_es_informativo(tmp_path):
    app = tmp_path / "app"
    (app / ".streamlit").mkdir(parents=True)
    (app / ".streamlit" / "config.toml").write_text(
        '[server]\naddress = "127.0.0.1"\nsslCertFile = "cert.pem"\nsslKeyFile = "key.pem"\n',
        encoding="utf-8")
    h = M3Configuracion().ejecutar({"app_dir": str(app)})
    assert all(x.severidad < Severidad.MEDIA for x in h)
    por_id = _por_id(h)
    assert por_id["M3-RED-BIND-LOCAL"].severidad == Severidad.INFO
    assert por_id["M3-TLS-OK"].severidad == Severidad.INFO


def test_m3_red_sin_config_recuerda_revisar(tmp_path):
    por_id = _por_id(M3Configuracion().ejecutar({"app_dir": str(tmp_path / "app")}))
    assert por_id["M3-RED-SIN-CONFIG"].severidad == Severidad.INFO


def test_m3_auditoria_grande_sin_rotacion(tmp_path):
    auditoria = tmp_path / "auditoria.jsonl"
    with open(auditoria, "wb") as f:
        f.truncate(51 * 1024 * 1024)        # 51 MB, sin ficheros rotados junto a él
    _blindar(auditoria)
    por_id = _por_id(M3Configuracion().ejecutar({"auditoria": str(auditoria)}))
    assert por_id["M3-AUDIT-ROTACION"].severidad == Severidad.BAJA


def test_m3_sin_rutas_declaradas(tmp_path):
    por_id = _por_id(M3Configuracion().ejecutar({"nombre": "objetivo sin config"}))
    assert por_id["M3-SIN-RUTAS"].severidad == Severidad.INFO


@pytest.mark.skipif(os.name == "nt", reason="os.stat no da bits POSIX fiables en Windows")
def test_m3_permisos_posix_laxos(tmp_path):
    usuarios = tmp_path / "usuarios.json"
    usuarios.write_text(json.dumps({"alice": {"rol": "ingeniero", "sal": "ab" * 16,
                                              "iteraciones": 200000, "hash": "cd" * 32}}),
                        encoding="utf-8")
    os.chmod(usuarios, 0o644)               # legible por grupo y otros
    por_id = _por_id(M3Configuracion().ejecutar({"usuarios": str(usuarios)}))
    assert por_id["M3-USUARIOS-PERMISOS"].severidad == Severidad.ALTA


@pytest.mark.skipif(os.name != "nt", reason="rama Windows: revisión manual de ACL")
def test_m3_permisos_windows_es_informativo(tmp_path):
    usuarios = tmp_path / "usuarios.json"
    usuarios.write_text(json.dumps({"alice": {"rol": "ingeniero", "sal": "ab" * 16,
                                              "iteraciones": 200000, "hash": "cd" * 32}}),
                        encoding="utf-8")
    por_id = _por_id(M3Configuracion().ejecutar({"usuarios": str(usuarios)}))
    assert por_id["M3-USUARIOS-PERMISOS"].severidad == Severidad.INFO
