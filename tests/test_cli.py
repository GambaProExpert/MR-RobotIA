"""Pruebas del comando: selector de escaneos (--escaneo, --excluir, --listar), --servidor,
--solo-declarado, la carpeta de --salida, el aislamiento de un módulo que falla y la omisión del
análisis del host cuando no hay servidor LLM. Son herméticas: procesos, tabla de puertos y
herramientas externas están simulados, y no se pregunta por red."""
import json
import sys
import types
from pathlib import Path

import pytest

from mrrobotia import cli, nucleo
from mrrobotia.herramientas import Deteccion
from mrrobotia.modulos import h2_identificacion as h2id
from mrrobotia.modulos.h3_host import H3Host
from mrrobotia.modulos.h3_puertos import H3Puertos
from mrrobotia.modulos.h3_ssh import H3Ssh
from mrrobotia.procesos import Proceso

ETIQUETAS = {"identificacion", "integridad", "config", "exposicion", "arranque", "cve", "ssh", "puertos", "vulns"}


def objetivo(**extra):
    base = {"nombre": "prueba", "host": "127.0.0.1",
            "autorizacion": {"tengo_autorizacion": True, "autorizado_por": "x", "ambito": "x", "fecha": "2026-01-01"}}
    return {**base, **extra}


def proceso_llama(puerto, pid=100):
    return Proceso(pid, "llama-server", ["/opt/llama-server", "-m", "/srv/m/modelo.gguf", "--port", str(puerto)])


@pytest.fixture
def entorno(monkeypatch):
    """Aísla el comando de la máquina real. Devuelve un objeto para configurar el escenario."""
    e = types.SimpleNamespace(procesos=[], instaladas=set())
    monkeypatch.setattr(h2id.procesos, "enumerar", lambda: list(e.procesos))
    monkeypatch.setattr(h2id.red, "tabla_puertos", lambda: "")
    monkeypatch.setattr(h2id.red, "sondear", lambda *a, **k: False)
    monkeypatch.setattr(h2id.red, "ip_rutable", lambda: None)
    monkeypatch.setattr(
        cli.herramientas, "detectar",
        lambda herramienta, overrides=None: Deteccion(herramienta.nombre in e.instaladas, None, None, None))
    return e


class Espia(nucleo.Modulo):
    """Módulo de prueba: anota si se ejecutó y qué contexto recibió."""
    nombre, titulo = "ESPIA", "módulo espía"

    def __init__(self, etiqueta="espia", requiere_servidor=False, falla=None):
        self.etiqueta_escaneo = etiqueta
        self.nombre = f"ESPIA-{etiqueta}"
        self.requiere_servidor = requiere_servidor
        self.falla = falla
        self.ejecuciones = 0

    def ejecutar(self, objetivo):
        self.ejecuciones += 1
        if self.falla:
            raise self.falla
        return []


def lanzar(monkeypatch, tmp_path, obj, *extra, nombre="informe"):
    """Ejecuta el comando y devuelve el JSON del informe."""
    ruta = tmp_path / "objetivo.json"
    ruta.write_text(json.dumps(obj), encoding="utf-8")
    salida = tmp_path / nombre
    monkeypatch.setattr(sys, "argv", ["mrrobotia", "--objetivo", str(ruta), "--salida", str(salida), *extra])
    cli.main()
    return json.loads(Path(str(salida) + ".json").read_text(encoding="utf-8"))


def ids(datos):
    return [h["id"] for h in datos["hallazgos"]]


# ------------------------------------------------------------------- --escaneo y --help
def test_ayuda_se_genera_del_registro(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["mrrobotia", "--help"])
    with pytest.raises(SystemExit) as salida:
        cli.main()
    assert salida.value.code == 0
    texto = " ".join(capsys.readouterr().out.split())
    for etiqueta in ETIQUETAS | {"servidor", "host", "activo", "pasivo", "todo"}:
        assert etiqueta in texto
    for opcion in ("--excluir", "--listar", "--servidor", "--solo-declarado"):
        assert opcion in texto


def test_ayuda_incluye_modulos_nuevos(monkeypatch):
    nuevo = Espia("zeta")
    monkeypatch.setattr(cli, "MODULOS", [*cli.MODULOS, nuevo])
    assert "zeta" in cli._ayuda_escaneo()


def test_grupo_servidor():
    assert cli.GRUPOS["servidor"] == {"exposicion", "arranque", "cve"}
    assert cli._resolver_escaneo("servidor") == ({"exposicion", "arranque", "cve"}, False)


def test_todas_las_etiquetas_son_validas():
    for etiqueta in ETIQUETAS:
        assert cli._resolver_escaneo(etiqueta) == ({etiqueta}, False)
    assert cli._resolver_escaneo("todo") == (None, False)
    assert cli._resolver_escaneo("pasivo") == (None, True)
    assert cli._resolver_escaneo("host,pasivo") == ({"ssh", "puertos", "vulns"}, True)


@pytest.mark.parametrize("valor", ["foo", "pasivo,foo", "todo,foo"])
def test_escaneo_desconocido(valor):
    with pytest.raises(SystemExit) as e:
        cli._resolver_escaneo(valor)
    assert "--escaneo: valor desconocido 'foo'" in str(e.value) and "arranque" in str(e.value)


# ---------------------------------------------------------------------------- --excluir
def test_excluir_etiqueta_de_todo():
    seleccion, _ = cli._resolver_escaneo("todo", "cve")
    assert seleccion == ETIQUETAS - {"cve"}


def test_excluir_un_grupo():
    seleccion, _ = cli._resolver_escaneo("todo", "host,servidor")
    assert seleccion == {"identificacion", "integridad", "config"}


def test_excluir_de_una_seleccion():
    assert cli._resolver_escaneo("servidor", "cve") == ({"exposicion", "arranque"}, False)


@pytest.mark.parametrize("excluir", ["identificacion", "cve,identificacion"])
def test_no_se_puede_excluir_la_identificacion(excluir):
    with pytest.raises(SystemExit) as e:
        cli._resolver_escaneo("todo", excluir)
    assert "no se puede excluir" in str(e.value) and "identificación" in str(e.value)


@pytest.mark.parametrize("excluir,mensaje", [("foo", "desconocido 'foo'"), ("todo", "'todo' no se puede excluir"),
                                             ("pasivo", "'pasivo' no se puede excluir")])
def test_excluir_invalido(excluir, mensaje):
    with pytest.raises(SystemExit) as e:
        cli._resolver_escaneo("todo", excluir)
    assert mensaje in str(e.value)


def test_excluir_de_punta_a_punta(entorno, monkeypatch, tmp_path):
    a, b = Espia("a"), Espia("b")
    monkeypatch.setattr(cli, "MODULOS", [a, b])
    datos = lanzar(monkeypatch, tmp_path, objetivo(), "--excluir", "b")
    assert (a.ejecuciones, b.ejecuciones) == (1, 0)
    assert datos["modulos"] == ["H2-ID", "ESPIA-a"]
    assert datos["escaneos"]["pedidos"] == ["identificacion", "a"]
    assert datos["escaneos"]["omitidos"] == [{"modulo": "ESPIA-b", "etiqueta": "b", "motivo": "excluido con --excluir"}]


# ----------------------------------------------------------------------------- --listar
def test_listar_no_necesita_objetivo(entorno, monkeypatch, capsys):
    entorno.instaladas = {"trivy"}
    monkeypatch.delenv("MRROBOTIA_OBJETIVO", raising=False)
    monkeypatch.setattr(sys, "argv", ["mrrobotia", "--listar"])
    cli.main()
    salida = capsys.readouterr().out
    for etiqueta in ETIQUETAS:
        assert f"  {etiqueta}  [" in salida
    for modulo in [cli.IDENTIFICACION, *cli.MODULOS]:
        assert f"[{modulo.nombre}]" in salida and modulo.descripcion in salida
    assert "tipo: híbrido" in salida and "tipo: pasivo" in salida
    assert "julius (no instalada)" in salida and "ssh-audit (no instalada)" in salida
    assert "trivy (instalada)" in salida
    assert "servidor: el servidor LLM" in salida and "= arranque, cve, exposicion" in salida
    assert "host: " in salida and "activo: " in salida and "pasivo: " in salida
    assert "no se puede excluir" in salida


def test_cada_modulo_declara_su_descripcion_y_tipo():
    for modulo in [cli.IDENTIFICACION, *cli.MODULOS]:
        assert modulo.descripcion and modulo.tipo in ("pasivo", "hibrido", "activo")
    assert cli.IDENTIFICACION.externa.nombre == "julius"
    assert {m.etiqueta_escaneo: m.externa.nombre for m in cli.MODULOS if m.externa} == {
        "ssh": "ssh-audit", "vulns": "trivy"}


# ---------------------------------------------------------------------------- --servidor
def test_servidor_forzado_distinto_avisa_del_conflicto(entorno, monkeypatch, tmp_path):
    entorno.procesos = [proceso_llama(8080)]
    obj = objetivo(endpoint="http://127.0.0.1:8080/v1/chat/completions")
    datos = lanzar(monkeypatch, tmp_path, obj, "--escaneo", "identificacion", "--servidor", "vllm")
    assert "H2-ID-CONFLICTO" in ids(datos)
    assert [s["tipo"] for s in datos["contexto"]["servidores"]] == ["vllm"]


def test_servidor_auto_no_fuerza_nada(entorno, monkeypatch, tmp_path):
    entorno.procesos = [proceso_llama(8080)]
    obj = objetivo(endpoint="http://127.0.0.1:8080/v1/chat/completions")
    datos = lanzar(monkeypatch, tmp_path, obj, "--escaneo", "identificacion", "--servidor", "auto")
    assert "H2-ID-CONFLICTO" not in ids(datos)
    assert [s["tipo"] for s in datos["contexto"]["servidores"]] == ["llama.cpp"]


def test_servidor_valor_invalido(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["mrrobotia", "--listar", "--servidor", "ollama"])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 2 and "invalid choice" in capsys.readouterr().err


def test_servidor_forzado_no_se_arrastra_entre_ejecuciones(entorno, monkeypatch, tmp_path):
    lanzar(monkeypatch, tmp_path, objetivo(endpoint="http://127.0.0.1:8080"), "--escaneo", "identificacion",
           "--servidor", "vllm")
    datos = lanzar(monkeypatch, tmp_path, objetivo(endpoint="http://127.0.0.1:8080"), "--escaneo", "identificacion")
    assert datos["contexto"]["servidores"] == []


# ----------------------------------------------------------------------- --solo-declarado
def test_solo_declarado_audita_un_servidor(entorno, monkeypatch, tmp_path):
    entorno.procesos = [proceso_llama(8080, pid=1), proceso_llama(8081, pid=2)]
    obj = objetivo(endpoint="http://127.0.0.1:8080")
    todos = lanzar(monkeypatch, tmp_path, obj, "--escaneo", "identificacion")
    assert sorted(s["puerto"] for s in todos["contexto"]["servidores"]) == [8080, 8081]
    datos = lanzar(monkeypatch, tmp_path, obj, "--escaneo", "identificacion", "--solo-declarado")
    assert [s["puerto"] for s in datos["contexto"]["servidores"]] == [8080]
    assert any("solo el servidor del endpoint" in n for n in datos["notas"])


def test_solo_declarado_no_prueba_otros_candidatos():
    destino = h2id.destino_declarado(objetivo(endpoint="http://127.0.0.1:8080"))
    assert [c.puerto for c in h2id._candidatos(destino, [], solo_declarado=True)] == [8080]
    assert len(h2id._candidatos(destino, [], solo_declarado=False)) > 1


def test_solo_declarado_sin_servidor_declarado(entorno, monkeypatch, tmp_path):
    ruta = tmp_path / "objetivo.json"
    ruta.write_text(json.dumps(objetivo(servidor="llama.cpp")), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["mrrobotia", "--objetivo", str(ruta), "--salida", str(tmp_path / "i"),
                                      "--solo-declarado"])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert "--solo-declarado" in str(e.value) and "endpoint" in str(e.value)
    assert not (tmp_path / "i.json").exists()


def test_solo_declarado_con_puerto_en_exposicion(entorno, monkeypatch, tmp_path):
    entorno.procesos = [proceso_llama(8080, pid=1), proceso_llama(8081, pid=2)]
    datos = lanzar(monkeypatch, tmp_path, objetivo(exposicion={"puerto": 8081}), "--escaneo", "identificacion",
                   "--solo-declarado")
    assert [s["puerto"] for s in datos["contexto"]["servidores"]] == [8081]


# ------------------------------------------------------------ H3 solo con servidor LLM
def test_los_modulos_del_host_requieren_servidor():
    assert H3Ssh.requiere_servidor and H3Puertos.requiere_servidor and H3Host.requiere_servidor
    assert {m.etiqueta_escaneo for m in cli.MODULOS if m.requiere_servidor} == {"ssh", "puertos", "vulns"}


def test_host_omitido_sin_servidor(entorno, monkeypatch, tmp_path):
    host, otro = Espia("host", requiere_servidor=True), Espia("otro")
    monkeypatch.setattr(cli, "MODULOS", [host, otro])
    datos = lanzar(monkeypatch, tmp_path, objetivo())
    assert (host.ejecuciones, otro.ejecuciones) == (0, 1)
    assert any("ESPIA-host" in n and "llama.cpp o vLLM" in n and "--servidor" in n and "'servidor'" in n
               for n in datos["notas"])
    assert datos["escaneos"]["omitidos"][0]["etiqueta"] == "host"
    assert "ESPIA-host" not in datos["modulos"]


@pytest.mark.parametrize("como", ["proceso", "declarado", "forzado"])
def test_host_se_ejecuta_con_servidor(entorno, monkeypatch, tmp_path, como):
    host = Espia("host", requiere_servidor=True)
    monkeypatch.setattr(cli, "MODULOS", [host])
    obj, extra = objetivo(endpoint="http://127.0.0.1:8080"), []
    if como == "proceso":
        entorno.procesos = [proceso_llama(8080)]
    elif como == "declarado":
        obj["servidor"] = "vllm"
    else:
        extra = ["--servidor", "llama.cpp"]
    datos = lanzar(monkeypatch, tmp_path, obj, *extra)
    assert host.ejecuciones == 1 and datos["escaneos"]["omitidos"] == []


def test_otro_servicio_no_cuenta_como_servidor_llm(entorno, monkeypatch, tmp_path):
    host = Espia("host", requiere_servidor=True)
    monkeypatch.setattr(cli, "MODULOS", [host])
    lanzar(monkeypatch, tmp_path, objetivo(endpoint="http://127.0.0.1:8080", servidor="ollama"))
    assert host.ejecuciones == 0


# ----------------------------------------------------------------------------- --salida
def test_salida_crea_la_carpeta(entorno, monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "MODULOS", [])
    lanzar(monkeypatch, tmp_path, objetivo(), "--escaneo", "identificacion", nombre="a/b/informe")
    assert (tmp_path / "a" / "b" / "informe.json").exists() and (tmp_path / "a" / "b" / "informe.md").exists()


def test_salida_imposible_falla_antes_de_escanear(entorno, monkeypatch, tmp_path):
    fichero = tmp_path / "fichero"
    fichero.write_text("x", encoding="utf-8")
    espia = Espia()
    monkeypatch.setattr(cli, "MODULOS", [espia])
    monkeypatch.setattr(cli.IDENTIFICACION, "ejecutar", lambda obj: pytest.fail("no debe escanear"))
    ruta = tmp_path / "objetivo.json"
    ruta.write_text(json.dumps(objetivo()), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["mrrobotia", "--objetivo", str(ruta), "--salida", str(fichero / "sub" / "inf")])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert "--salida" in str(e.value) and "No se ha escaneado nada" in str(e.value)
    assert espia.ejecuciones == 0


@pytest.mark.parametrize("sufijo", ["/", "\\"])
def test_salida_no_puede_ser_una_carpeta(tmp_path, sufijo):
    with pytest.raises(SystemExit) as e:
        cli._preparar_salida(str(tmp_path) + sufijo)
    assert "prefijo" in str(e.value)


def test_salida_con_nombre_de_carpeta_existente(tmp_path):
    (tmp_path / "informe.json").mkdir()
    with pytest.raises(SystemExit) as e:
        cli._preparar_salida(str(tmp_path / "informe"))
    assert "--salida" in str(e.value)


# ----------------------------------------------------------- un módulo que falla
def test_un_modulo_que_falla_no_aborta(entorno, monkeypatch, tmp_path):
    malo = Espia("malo", falla=RuntimeError("secreto-en-el-mensaje /ruta/privada"))
    bueno = Espia("bueno")
    monkeypatch.setattr(cli, "MODULOS", [malo, bueno])
    ruta = tmp_path / "objetivo.json"
    ruta.write_text(json.dumps(objetivo()), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["mrrobotia", "--objetivo", str(ruta), "--salida", str(tmp_path / "i")])
    cli.main()
    texto = (tmp_path / "i.json").read_text(encoding="utf-8") + (tmp_path / "i.md").read_text(encoding="utf-8")
    datos = json.loads((tmp_path / "i.json").read_text(encoding="utf-8"))
    error = next(h for h in datos["hallazgos"] if h["id"] == "ESPIA-malo-ERROR")
    assert (error["severidad"], error["estado"], error["evidencia"]) == ("INFO", "sin_concluir", "RuntimeError")
    assert bueno.ejecuciones == 1
    assert "secreto-en-el-mensaje" not in texto and "/ruta/privada" not in texto


def test_la_identificacion_que_falla_no_aborta(entorno, monkeypatch, tmp_path):
    def revienta(obj):
        raise OSError("ruta privada")

    otro = Espia()
    monkeypatch.setattr(cli, "MODULOS", [otro])
    monkeypatch.setattr(cli.IDENTIFICACION, "ejecutar", revienta)
    datos = lanzar(monkeypatch, tmp_path, objetivo())
    assert "H2-ID-ERROR" in ids(datos) and otro.ejecuciones == 1


# ------------------------------------------------------------ qué se pidió y qué se omitió
def test_informe_dice_que_se_pidio_y_que_se_omitio(entorno, monkeypatch, tmp_path):
    a, b, c = Espia("a"), Espia("b"), Espia("c", requiere_servidor=True)
    monkeypatch.setattr(cli, "MODULOS", [a, b, c])
    datos = lanzar(monkeypatch, tmp_path, objetivo(), "--escaneo", "a,c")
    assert datos["escaneos"]["pedidos"] == ["identificacion", "a", "c"]
    omitidos = {o["etiqueta"]: o["motivo"] for o in datos["escaneos"]["omitidos"]}
    assert omitidos == {"b": "no seleccionado con --escaneo", "c": "no se ha identificado un servidor llama.cpp ni vLLM"}
    md = (tmp_path / "informe.md").read_text(encoding="utf-8")
    assert "Escaneos pedidos: identificacion, a, c" in md and "- b (ESPIA-b): no seleccionado con --escaneo" in md


# ------------------------------------------------------------------ errores del objetivo
def test_objetivo_inexistente_o_invalido(monkeypatch, tmp_path):
    for contenido in (None, "{no es json"):
        ruta = tmp_path / "o.json"
        if contenido is not None:
            ruta.write_text(contenido, encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["mrrobotia", "--objetivo", str(ruta), "--salida", str(tmp_path / "i")])
        with pytest.raises(SystemExit) as e:
            cli.main()
        assert "objetivo" in str(e.value)
