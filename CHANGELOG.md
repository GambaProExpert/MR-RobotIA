# Registro de cambios

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el proyecto se adhiere al [Versionado Semántico](https://semver.org/lang/es/).

## [0.7.0] - 2026-11-13

### Cambiado (ruptura: opciones renombradas, sin alias de las antiguas)
- **El comando pasa a opciones cortas y en inglés**, con ayuda (`--help`), `--list` y mensajes
  de error del comando en inglés. Los hallazgos del informe, los mensajes de los módulos y las
  claves del fichero de objetivo siguen en español.

| Antes | Ahora |
|---|---|
| `--objetivo` | `-t`, `--target` |
| `--permitir-activos` | `-a`, `--active` |
| `--salida` | `-o`, `--out` |
| `--escaneo` | `-s`, `--scan` |
| `--excluir` | `-x`, `--skip` |
| `--listar` | `-l`, `--list` |
| `--servidor` | `--server` |
| `--solo-declarado` | `--declared-only` |

- **Etiquetas de escaneo:** `identificacion` pasa a `id`, `integridad` a `integrity`, `exposicion`
  a `exposure`, `arranque` a `startup` y `puertos` a `ports` (`config`, `cve`, `ssh` y `vulns`
  no cambian).
- **Grupos:** `todo` pasa a `all`, `activo` a `active`, `servidor` a `server` y `pasivo` a
  `passive` (`host` no cambia).
- **Variables de entorno:** `MRROBOTIA_OBJETIVO` pasa a `MRROBOTIA_TARGET` y
  `MRROBOTIA_PERMITIR_ACTIVOS` a `MRROBOTIA_ACTIVE`.
- El informe usa las etiquetas nuevas en «Escaneos pedidos» y en los motivos de omisión.

### Añadido
- `README.md` en inglés y `README.es.md` en español, ambos con un inicio rápido y la estructura
  del fichero de objetivo comentada clave por clave.

## [0.6.0] - 2026-11-09

### Añadido
- **Identificación previa (H2-ID)**: antes de auditar, MRRobotIA averigua qué servidor hay
  (llama.cpp, vLLM u otro), su versión, cómo se arrancó (opciones saneadas y entorno, solo
  presencia de secretos) y en qué sistema (Windows, Linux, WSL). Procesos locales, tabla de
  puertos y, con sondeo activo, HTTP; Julius opcional para lo que los perfiles no reconocen. El
  resultado (`Contexto`) llega a todos los módulos y se vuelca en el informe («Qué se ha
  identificado»). Avisa si lo declarado en el objetivo contradice lo detectado.
- **Perfiles por servidor** (`perfiles/`): llama.cpp (completo, probado contra un servidor real) y
  vLLM (a partir del código de la 0.33.0, **sin validar contra un servidor real**), más un
  perfil genérico para servidores compatibles con OpenAI.
- **H2 por servidor**: la exposición se evalúa para cada servidor identificado, con las
  comprobaciones comunes (enlace, propietario, CORS, `Host`, TLS) y las propias de su perfil. Una
  causa da un único hallazgo.
- **H2-ARRANQUE** (escaneo `arranque`): opciones y entorno de arranque del servidor, pasivo.
- **H2-CVE** (escaneo `cve`): versión del servidor frente a avisos de seguridad incluidos
  (48 de llama.cpp y 140 de vLLM); una coincidencia por versión es un indicio (`potencial`).
- **Selector del comando**: `--listar` (escaneos, grupos, tipo pasivo/híbrido y herramienta
  externa), `--excluir`, grupo `servidor` (`exposicion`, `arranque`, `cve`), `--servidor
  {auto,llama.cpp,vllm}` y `--solo-declarado`. La ayuda de `--escaneo` se genera del registro de
  módulos. El informe indica qué escaneos se pidieron y cuáles se omitieron, con el motivo.
- Pruebas del comando (`tests/test_cli.py`) y de los cambios de M2 y H3-PUERTOS.

### Cambiado
- **El análisis del host (H3-SSH, H3-PUERTOS, H3-HOST) solo corre en máquinas con servidor
  llama.cpp o vLLM** (identificado, declarado o forzado); si no, se omite con una nota que explica
  cómo forzarlo.
- H3-PUERTOS reconoce los puertos por defecto de cada perfil (llama.cpp `9931` y `8080`, vLLM
  `8000`) y los canales internos de cada servidor.
- La carpeta de `--salida` se crea si no existe; si no se puede crear o escribir, el comando falla
  **antes** de escanear en lugar de perder el escaneo al final.

### Corregido
- Un módulo que falla ya no aborta la auditoría: queda un hallazgo INFO `<módulo>-ERROR`
  (`sin_concluir`, solo con el tipo de la excepción) y los demás siguen.
- `--help` listaba solo parte de las etiquetas de `--escaneo`.
- En Windows, la tabla de puertos se lee con la API del sistema (`GetExtendedTcpTable`): en algunos
  equipos, `netstat -ano` mostraba solo una parte de los puertos, distinta en cada lectura.
- H3-PUERTOS: en Windows, los puertos inesperados del rango dinámico (49152-65535), casi siempre
  RPC del sistema, daban unos veinte hallazgos; ahora son uno solo, `H3-PUERTOS-DINAMICOS`, con su
  número y la lista de puertos.
- M2: un `sha256` declarado que no tiene 64 caracteres hexadecimales ya no se informa como
  artefacto alterado, sino como INFO `sin_concluir` («el valor declarado no es válido»).
- Un host no local ya no usa la tabla de puertos ni el `sshd_config` del equipo auditor.
- El objetivo de ejemplo es genérico (sin rutas ni datos de ningún despliegue concreto) y el
  README deja de documentar la clave inexistente `builds_vulnerables`.

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
  - `mrrobotia/red.py`: utilidades de red/SO compartidas (tabla de puertos, enlace, sondeo, propietario).
  - Atacantes A5/A4/A3; marcos OWASP LLM10/LLM03/LLM02, MITRE ATLAS, NIST AI 600-1.
- **Selector `--escaneo`**: elige qué correr por etiqueta (`integridad, config, exposicion, ssh,
  puertos, vulns`) o grupo (`todo, host, activo, pasivo`); `pasivo` fuerza a omitir todo sondeo
  activo. Cada módulo declara su `etiqueta_escaneo`.
- Claves de objetivo `servidor`, `ssh`, `puertos`, `host_trivy`.

### Cambiado
- La herramienta pasa a llamarse **MRRobotIA** por motivos de derechos de autor: el paquete
  Python es `mrrobotia`, el comando de consola es `mrrobotia`, y las variables de entorno son
  `MRROBOTIA_OBJETIVO` / `MRROBOTIA_PERMITIR_ACTIVOS`.

## [0.4.0] - 2026-11-06

### Añadido
- **Módulo H2 — Inventario y exposición del servidor LLM** (`mrrobotia.modulos.h2_exposicion`),
  para **llama.cpp (llama-server)**. Módulo HÍBRIDO: parte PASIVA siempre (enlace de red del
  puerto vía `netstat`/`ss`, claves de proveedor en el entorno —solo NOMBRES—, propietario del
  proceso best-effort) y parte ACTIVA gated (sondeo del endpoint: sin API key, `/slots` —fuga de
  prompts—, `/props` —ruta del modelo y build—, `/v1/models`, `/metrics`, CORS reflejado/DNS
  rebinding, HTTP sin TLS, interfaz web, y severidad compuesta de exposición). **Nunca vuelca
  prompts ni valores de entorno.** Atacantes A5/A3; marcos OWASP LLM10/LLM02/LLM03, MITRE ATLAS,
  NIST AI 600-1. Clave de objetivo `endpoint` + `exposicion` (`puerto`, `bind_esperado`,
  `proxy_autenticador`, `api_key_esperada`, `builds_vulnerables`) y `tests/test_h2.py`.
- **Gating de sondeo activo granular**: atributo `Modulo.activos_ok` (lo pone el CLI con
  `--permitir-activos`/`MRROBOTIA_PERMITIR_ACTIVOS` + `permitir_activos`), para módulos híbridos
  cuya parte pasiva debe correr siempre.

### Cambiado
- El CLI registra H2 y **desvincula el prober propio M1**: `m1_robustez.py` queda en disco, sin
  cablear, a sustituir por garak en H4. Se conservan `MRROBOTIA_OBJETIVO` y `MRROBOTIA_PERMITIR_ACTIVOS`.
  Objetivo de ejemplo con `endpoint` + `exposicion`.

## [0.3.0] - 2026-11-06

### Añadido
- **Núcleo orquestador de herramientas externas** (`mrrobotia.herramientas`): MRRobotIA pasa
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
- **Módulo M3 — Auditoría de configuración** (`mrrobotia.modulos.m3_configuracion`):
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
- M3 registrado en la CLI (`mrrobotia`/`python -m mrrobotia`), tras M2.
- Claves nuevas del objetivo de ejemplo (`usuarios`, `auditoria`/`dir_logs`, `app_dir`)
  y pruebas `tests/test_m3.py` (fixtures sintéticas con `tmp_path`, sin datos reales).

## [0.1.0] - 2026-11-06

### Añadido
- **Núcleo del auditor** (`mrrobotia.nucleo`): modelo de `Hallazgo` con severidades
  (INFO…CRITICA), carga de objetivo con **autorización explícita** (deniega por
  defecto; un host no local exige confirmación aparte) e **informe** en Markdown y
  JSON ordenado por severidad.
- **Módulo M2 — Integridad de artefactos** (`mrrobotia.modulos.m2_integridad`):
  verificación SHA-256 de `.gguf` y bases vectoriales contra un manifiesto; detecta
  artefactos ausentes, alterados, sin hash de referencia y manifiestos sin firmar
  (atacantes A3 y A4 del modelo de amenazas).
- **Interfaz de línea de órdenes** `mrrobotia` (y `python -m mrrobotia`) con las opciones
  `--objetivo`, `--permitir-activos` y `--salida`.
- **Empaquetado instalable** con src-layout (`pip install -e .`), ejemplo de objetivo
  en `ejemplos/` y batería de pruebas con pytest.
