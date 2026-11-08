# Registro de cambios

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el proyecto se adhiere al [Versionado Semántico](https://semver.org/lang/es/).

## [0.5.0] - 2026-11-08

### Añadido
- **Hito H3 — Seguridad del host** (Capa 1), con tres módulos y un selector de escaneo:
  - **H3-SSH** (`modulos/h3_ssh.py`): endurecimiento de SSH. PASIVO: lee `sshd_config` (perfil CIS:
    PermitRootLogin, contraseñas vacías, autenticación por contraseña, cifrados/MAC/KEX débiles,
    MaxAuthTries…). ACTIVO (gated): `ssh-audit` contra el servicio. Ignora las huellas de host keys.
  - **H3-PUERTOS** (`modulos/h3_puertos.py`): puertos abiertos innecesarios/inseguros frente a una
    línea base por servidor (vLLM `:8000`/`:8265`, llama.cpp `:8080`); marca bases de datos, RDP/SMB,
    Redis, Ray, etc. PASIVO (`netstat`/`ss`) + barrido de conexión ACTIVO (gated). Evidencia: solo
    puerto/bind/pid, nunca banners.
  - **H3-HOST** (`modulos/h3_host.py`): **Trivy** (`trivy fs`, offline) para CVEs, malas
    configuraciones y secretos; PASIVO. Nunca vuelca el valor del secreto (solo regla@fichero:línea).
  - `mrrobot/red.py`: utilidades de red/SO compartidas (tabla de puertos, enlace, sondeo, propietario).
  - Atacantes A5/A4/A3; marcos OWASP LLM10/LLM03/LLM02, MITRE ATLAS, NIST AI 600-1.
- **Selector `--escaneo`**: elige qué correr por etiqueta (`integridad, config, exposicion, ssh,
  puertos, vulns`) o grupo (`todo, host, activo, pasivo`); `pasivo` fuerza a omitir todo sondeo
  activo. Cada módulo declara su `etiqueta_escaneo`.
- Claves de objetivo `servidor`, `ssh`, `puertos`, `host_trivy`.

## [0.4.0] - 2026-11-06

### Añadido
- **Módulo H2 — Inventario y exposición del servidor LLM** (`mrrobot.modulos.h2_exposicion`),
  para **llama.cpp (llama-server)**. Módulo HÍBRIDO: parte PASIVA siempre (enlace de red del
  puerto vía `netstat`/`ss`, claves de proveedor en el entorno —solo NOMBRES—, propietario del
  proceso best-effort) y parte ACTIVA gated (sondeo del endpoint: sin API key, `/slots` —fuga de
  prompts—, `/props` —ruta del modelo y build—, `/v1/models`, `/metrics`, CORS reflejado/DNS
  rebinding, HTTP sin TLS, interfaz web, y severidad compuesta de exposición). **Nunca vuelca
  prompts ni valores de entorno.** Atacantes A5/A3; marcos OWASP LLM10/LLM02/LLM03, MITRE ATLAS,
  NIST AI 600-1. Clave de objetivo `endpoint` + `exposicion` (`puerto`, `bind_esperado`,
  `proxy_autenticador`, `api_key_esperada`, `builds_vulnerables`) y `tests/test_h2.py`.
- **Gating de sondeo activo granular**: atributo `Modulo.activos_ok` (lo pone el CLI con
  `--permitir-activos`/`MRROBOT_PERMITIR_ACTIVOS` + `permitir_activos`), para módulos híbridos
  cuya parte pasiva debe correr siempre.

### Cambiado
- El CLI registra H2 y **desvincula el prober propio M1**: `m1_robustez.py` queda en disco, sin
  cablear, a sustituir por garak en H4. Se conservan `MRROBOT_OBJETIVO` y `MRROBOT_PERMITIR_ACTIVOS`.
  Objetivo de ejemplo con `endpoint` + `exposicion`.

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
