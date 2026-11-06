# Registro de cambios

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el proyecto se adhiere al [Versionado Semántico](https://semver.org/lang/es/).

## [0.3.0] - 2026-11-06

### Añadido
- **Núcleo orquestador de herramientas externas** (`mrrobot.herramientas`): MRRobot pasa
  a **orquestar** herramientas ya consolidadas (garak, promptfoo, Trivy, DeepEval…) y
  **normalizar** su salida a `Hallazgo`, en lugar de reimplementarlas (ver `HITOS.md`).
  - `Herramienta`/`Deteccion`/`Resultado`; `detectar()` (ruta del `PATH` o de
    `objetivo['herramientas'][nombre]['ruta']`, con versión best-effort); `ejecutar()`
    (subprocess con timeout, **sin `shell=True`**, no propaga excepciones); y la base
    `ModuloHerramienta`: si la herramienta no está instalada emite un hallazgo INFO con
    cómo instalarla; si está, antepone un hallazgo de trazabilidad con la versión usada.
  - Solo biblioteca estándar; las herramientas externas son prerrequisitos del sistema.
  - Clave de objetivo `herramientas` (overrides de ruta/timeout) y `tests/test_herramientas.py`
    (sin herramientas externas: usan el propio intérprete de Python).
- Hoja de ruta por capas en `HITOS.md` (alcance: LLM + RAG + host).

### Cambiado
- El roadmap pasa del esquema M1–M5 a **hitos por herramienta y capa** (H0–H6). El prober
  propio `modulos/m1_robustez.py` queda pendiente de reconciliar con garak (H4).

## [0.2.0] - 2026-11-06

### Añadido
- **Módulo M3 — Auditoría de configuración** (`mrrobot.modulos.m3_configuracion`):
  módulo pasivo y de solo lectura que, a partir de las rutas declaradas en el objetivo
  (`usuarios`, `auditoria`/`dir_logs` y, opcional, `app_dir`), comprueba:
  - `usuarios.json`: PBKDF2 con iteraciones suficientes (>= 100000), sal presente y de
    longitud razonable (>= 16 bytes) y hash presente; detecta campos con pinta de
    contraseña en claro (CRÍTICA); revisa permisos (ALTA en POSIX si es legible por
    grupo/otros, INFO en Windows recordando revisar las ACL NTFS a mano).
  - Registro de auditoría: avisa (ALTA) si alguna entrada guarda el **texto** de la
    pregunta en vez de solo su hash; rotación por tamaño (> 50 MB) y permisos.
  - TLS y enlace de red: si existe `.streamlit/config.toml` informa de `server.address`
    (ALTA si enlaza a `0.0.0.0`) y de `sslCertFile`/`sslKeyFile`; si no, recuerda que el
    enlace a 127.0.0.1 y el TLS dependen del arranque.
  - Atacantes A3 (acceso a disco) y A5 (exposición); marcos OWASP LLM02 y LLM10,
    NIST AI 600-1 (2.4, 2.9), MITRE ATLAS AML.T0049. **Nunca imprime secretos**: solo
    recuentos y nombres de campo, con hashes y valores truncados u omitidos.
- M3 registrado en la CLI (`mrrobot`/`python -m mrrobot`), tras M2.
- Claves nuevas del objetivo de ejemplo (`usuarios`, `auditoria`/`dir_logs`, `app_dir`)
  y pruebas `tests/test_m3.py` (fixtures sintéticas con `tmp_path`, sin datos reales).

## [0.1.0] - 2026-11-06

### Añadido
- **Núcleo del auditor** (`mrrobot.nucleo`): modelo de `Hallazgo` con severidades
  (INFO…CRITICA), carga de objetivo con **autorización explícita** (deniega por
  defecto; un host no local exige confirmación aparte) e **informe** en Markdown y
  JSON ordenado por severidad.
- **Módulo M2 — Integridad de artefactos** (`mrrobot.modulos.m2_integridad`):
  verificación SHA-256 de `.gguf` y bases vectoriales contra un manifiesto; detecta
  artefactos ausentes, alterados, sin hash de referencia y manifiestos sin firmar
  (atacantes A3 y A4 del modelo de amenazas).
- **Interfaz de línea de órdenes** `mrrobot` (y `python -m mrrobot`) con las opciones
  `--objetivo`, `--permitir-activos` y `--salida`.
- **Empaquetado instalable** con src-layout (`pip install -e .`), ejemplo de objetivo
  en `ejemplos/` y batería de pruebas con pytest.
