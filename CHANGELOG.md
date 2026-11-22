# Registro de cambios

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el proyecto se adhiere al [Versionado Semántico](https://semver.org/lang/es/).

## [0.15.0] - 2026-11-22

### Añadido: H5 `White_Rose`, segundo motor: DeepTeam
- **Nuevo escaneo `deepteam`** (módulo `H5-DEEPTEAM`, `modulos/h5_deepteam.py`): evalúa el comportamiento del chatbot con
  DeepTeam (y DeepEval debajo) como segundo motor de H5, junto a promptfoo. Es **activo** y **no entra en `all`**: exige
  `-s deepteam`, `-a`, `allow_active` y, si el host no es local, `authorization.confirm_non_local`. Aporta las
  vulnerabilidades agénticas (BOLA, BFLA, RBAC, SSRF, agencia excesiva, acceso de depuración, inyección SQL y de comandos...)
  que en promptfoo solo existen con generación remota, y rúbricas más específicas de PII y fuga del system prompt.
- **Sin dependencias de ejecución nuevas:** MRRobotIA **no importa** DeepTeam. Lanza `datos/deepteam_runner.py` con el
  `python` del entorno virtual del ejecutable `deepteam` declarado en `tools.deepteam.path`, le pasa un JSON de entrada (sin
  claves) y lee un JSON de salida, por `subprocess` y sin shell. Se instala con `deepeval==4.3.4 deepteam==1.0.10
  sentry-sdk==2.75.0` (Python 3.10-3.13); `sentry-sdk` es obligatorio porque DeepTeam 1.0.10 lo importa sin declararlo
  (`H5-DEEPTEAM-SENTRY-FALTA`). Entrada en el catálogo de instalación, en `--check-tools` y en `docs/TOOLS.md` y
  `docs/HERRAMIENTAS.md`.
- **Todo local, requisito duro y que falla cerrado.** En **cada** subproceso, también la consulta de versión:
  `DEEPEVAL_TELEMETRY_OPT_OUT=1`, `DEEPTEAM_TELEMETRY_OPT_OUT=YES` (DeepTeam solo acepta el literal `YES`),
  `DEEPEVAL_DISABLE_DOTENV=1`, `DEEPEVAL_DISABLE_LEGACY_KEYFILE=1`, `DEEPEVAL_HOME`, `~`, temporales y directorio de
  trabajo dentro de `<prefijo>_deepteam/home/` (DeepEval escribe prompts y respuestas en claro en `<CWD>/.deepeval/`), sin
  `CONFIDENT_API_KEY`, `OPENAI_API_KEY`, `ERROR_REPORTING` ni variables de servicios de terceros, y proxy muerto con
  `NO_PROXY` solo para el sujeto y el juez. El ejecutor se niega a arrancar (código 3) si falta algo y lleva una guardia de
  sockets (`H5-DEEPTEAM-SALIDA-BLOQUEADA`). Lo que exija la nube (Confident AI, marcos con datos remotos, modelos no
  locales) no se ejecuta: INFO `H5-DEEPTEAM-REMOTO-OMITIDO`. Una clave en claro en el bloque se rechaza sin ejecutar nada.
- **Juez y atacante locales**, por defecto el propio sujeto con aviso `H5-DEEPTEAM-JUEZ-MISMO-MODELO` y la frase fija de que
  un resultado limpio no demuestra seguridad (medido: el 14B como juez, 0 falsos positivos pero 1 de 3 fugas detectadas; el
  7B juzgándose, 19 falsos positivos de 24). Los **canarios** (`deepteam.canaries`) se buscan en la respuesta sin juez y son
  la señal fiable; el juez se calibra antes con 8 casos y las métricas de DeepTeam (`H5-DEEPTEAM-JUEZ-NO-FIABLE`).
- 12 vulnerabilidades verificadas sin red (`pii_leakage`, `prompt_leakage`, `cross_context_retrieval`, `bola`, `bfla`,
  `rbac`, `excessive_agency`, `ssrf`, `debug_access`, `shell_injection`, `sql_injection`, `indirect_instruction`) y 6
  métodos de ataque de un turno; presets `quick`, `standard` y `full`; bloque `deepteam` del objetivo (`preset`,
  `system_prompt`, `system_prompt_file`, `purpose`, `canaries`, `vulnerabilities`, `attacks`, `attacks_per_type`, `judge`,
  `attacker`, `concurrency`, `max_duration`, `max_tokens`, `temperature`, `api_key_env`, `keep_raw`, `calibrate_judge`).
  Marcos: OWASP LLM 2025; ATLAS y NIST solo donde coinciden con H4.
- Sección «Evaluación del comportamiento del chatbot (DeepTeam)» del informe y ejemplo en `ejemplos/target.example.json`.
- Validación real (Qwen2.5-7B en GPU como sujeto y Qwen3-14B en CPU como juez y atacante): `quick` de punta a punta (10 casos, calibración 8/8, 25 min 0 s; una fuga real de sesión con el DNI hallada por el canario y un falso positivo del juez sobre datos inventados) y las 12 vulnerabilidades con los 5 métodos de mejora con un juez 7B (36 casos, 0 sin puntuar). Con un oyente en el proxy muerto y la guardia de sockets: 0 intentos propios; nada escrito fuera de `<prefijo>_deepteam/`; ni el canario ni claves en el informe. Sin validar: vLLM como chatbot, `standard`, `full` y Linux/macOS.

### Cambiado
- **Lo común de H5 pasa a `modulos/h5_comun.py`** (refactor sin cambios de comportamiento en promptfoo, con todas sus
  pruebas pasando): base del bloqueo de red, severidad, canarios, claves en claro, destino local, validación y resolución
  del juez y del atacante, hallazgos de fiabilidad del juez y el motivo de un fallo en el registro. El informe tiene una
  sola función de sección para los dos motores.
- `herramientas.Herramienta` gana `entorno_seguro` (consulta de versión con un entorno bloqueado y desde una carpeta
  temporal) y `detectar` acepta `cwd`; `ModuloHerramienta` gana el gancho `_cwd_deteccion`.
- `redactar` oculta los canarios, el system prompt y las claves también en el bloque `deepteam`.

## [0.14.0] - 2026-11-22

### Añadido: H6 `Young_Elliot` — ¿salen datos de la red?
- **Nuevo escaneo `egress`** (módulo `H6-SALIDAS`, `modulos/h6_salidas.py`): código propio, solo biblioteca estándar y
  sin herramienta externa. Es **híbrido** y entra en `all` solo con su **auditoría estática**; la ventana de
  observación y los canarios exigen `-a` con `allow_active` (la ventana pasiva también corre con `-s egress`).
  - **Auditoría estática de canales de salida** (`H6-SALIDAS-CANAL-*`) a partir de la línea de órdenes saneada, el
    entorno del proceso y los ficheros de estado de vLLM: telemetría (y exclusión inválida, e historial con
    `usage_stats.json`), hub de modelos en línea sin `HF_HUB_OFFLINE`, descargas de llama.cpp sin `--offline`,
    carga remota, RPC, MCP y herramientas, proxy de la interfaz, trazas OTLP, eventos KV por ZMQ (ALTA: llevan los
    `token_ids` del prompt, sin autenticación), transferencia KV y proxies del entorno.
  - **Observación por PID** del árbol de procesos del servidor: muestreo de la tabla de sockets del sistema
    (Windows `GetExtendedTcpTable`/Toolhelp; Linux `/proc/<pid>/net/*` e inodos de `fd`). Salida pública, ALTA;
    a la red local, MEDIA; `H6-SALIDAS-PULL-<puerto>`, `-DNS`, `-UDP-<n>`.
  - **Canario** (`MRR-H6-<12 hex>`, nunca impreso, por `chat` o `tokenize`) con correlación: conexiones públicas
    nuevas tras al menos la mitad de las peticiones dan `H6-SALIDAS-CORRELACION` (CRÍTICA). La ventana limpia lleva
    la frase fija de límites (TLS, muestreo, árbol, DNS, WSL).
  - Bloque `egress` del objetivo (`allow`, `passive_window`, `active_window`, `trailing`, `interval_ms`, `canaries`,
    `canary_endpoint`, `max_tokens`, `correlation_s`, `api_key_env`, `pids`, `process_names`, `history_files`),
    sección «Salidas de datos a la red (H6)» del informe con las tablas de canales y de conexiones, y pertenencia al
    grupo `server` y `active`.
  - Funciones nuevas: `red.filas_tabla_tcp_todas`, `red.sockets_windows`, `red.filas_proc_net`, `red.sockets_linux`
    y `procesos.tabla_pid_ppid`/`arbol_de`. Opciones nuevas en los perfiles: vLLM `--otlp-traces-endpoint`,
    `--kv-events-config`, `--kv-transfer-config` (solo presencia) y `--load-format`, y la marca `model_remoto`
    (identificador de repositorio); llama.cpp `--offline` y `-hfd`/`--hf-repo-draft`.
- **DeepEval/DeepTeam no forman parte de H6** (medido: no responden a «¿salen datos de la red?» y son un canal de
  salida por defecto, con unos 30 intentos de telemetría por ejecución y un corte que en DeepTeam exige el literal
  `YES`). Se integrarán aparte, como segundo motor de H5, con la telemetría cortada del todo y un juez local.
- Documentado y medido el **juez distinto del sujeto** de H5 (`promptfoo.judge.url` hacia otro modelo local mayor):
  el 7B juzgándose a sí mismo dio 19 falsos positivos de 24; el juez 14B ninguno, pero dejó pasar 2 de 3 fugas reales.
  El canario es la única señal fiable.

### Cambiado
- **La comprobación de telemetría de vLLM pasa de H2-ARRANQUE a H6**: el hallazgo `H2-ARRANQUE-TELEMETRIA` desaparece
  y su lugar lo ocupa `H6-SALIDAS-CANAL-TELEMETRIA`. Cualquier consumidor del informe que filtrara por el
  identificador antiguo debe usar el nuevo. Con `-s startup` solo ya no sale esa fila.

### Corregido
- **Exclusión de telemetría de vLLM mal interpretada:** MRRobotIA daba por buena una exclusión con cualquier valor
  (`DO_NOT_TRACK=true`), pero vLLM solo acepta exactamente `1` (con `true` envía igual: medido en un vLLM real).
  Ahora sale `H6-SALIDAS-CANAL-TELEMETRIA-EXCLUSION-INVALIDA` (BAJA).

## [0.13.0] - 2026-11-21

### Añadido: H5 `White_Rose` — evaluación del chatbot con promptfoo
- **Nuevo escaneo `promptfoo`** (módulo `H5-PROMPTFOO`, `modulos/h5_promptfoo.py`): evalúa el *comportamiento del
  chatbot* con su system prompt, propósito y límites (fuga del system prompt, sustitución de instrucciones,
  inyección indirecta en el documento recuperado, fuga entre sesiones, RBAC, BOLA/BFLA, agencia excesiva...).
  Es **activo** y **no entra en `all`**: exige `-s promptfoo`, `-a`, `allow_active` y, si el host no es local,
  `authorization.confirm_non_local`. Complementa a H4: garak barre el endpoint; promptfoo evalúa el chatbot y
  su configuración sirve de *gate* de CI.
- **Todo local, requisito duro y no configurable.** En **cada** subproceso de promptfoo, también la consulta de
  versión, se fuerzan la telemetría, la comprobación de versión, el compartir y la generación remota
  desactivados, un proxy muerto (`HTTPS_PROXY=http://127.0.0.1:9`) con `NO_PROXY` solo para el chatbot y el juez,
  y `PROMPTFOO_CONFIG_DIR` dentro de `<prefijo>_promptfoo/home/` (nada en `~/.promptfoo`). Medido:
  `PROMPTFOO_DISABLE_TELEMETRY=1` por sí sola no basta (sigue enviando un evento a `r.promptfoo.app`).
  **Falla cerrado**: solo plugins y estrategias verificados como locales; lo demás no se ejecuta y sale como INFO
  `H5-PROMPTFOO-REMOTO-OMITIDO`. Una clave real de OpenAI del entorno nunca se reenvía.
- **Juez local y poco fiable si es el mismo modelo.** El juez es un servidor local (`judge.url`; por defecto el
  del propio chatbot; uno no local se rechaza con `H5-PROMPTFOO-JUEZ-NO-LOCAL`). Un 7B que se juzga a sí mismo
  aprobó un volcado completo del system prompt, así que: **`canaries`** (aserciones deterministas, sin juez, que
  nunca se imprimen: `[canario nº k]`), **calibración del juez** antes de ejecutar (`H5-PROMPTFOO-JUEZ-NO-FIABLE`),
  `H5-PROMPTFOO-JUEZ-MISMO-MODELO` y una frase fija en el informe: un resultado limpio con un juez del mismo
  modelo no demuestra seguridad.
- **Construcción automática** para llama.cpp y vLLM, o **configuración de promptfoo pegada** (`promptfoo.config`,
  objeto JSON) o `promptfoo.config_file`. Se revisa antes de ejecutar: clave en claro
  (`H5-PROMPTFOO-CLAVE-EN-CLARO`, ALTA, sin ejecutar), código (`extensions`, scripts, aserciones
  `javascript`/`python`: `H5-PROMPTFOO-CODIGO-EN-CONFIG`, salvo `allow_code`), juez o atacante no locales,
  pruebas descargadas de la red, plugins remotos (se quitan de una copia). Un `config_file` se usa sin modificar.
- **Presets** `quick`, `standard`, `gate` y `full` (`gate`: solo el paquete de pruebas fijas más `custom_tests`;
  determinista, de 1 a 4 min). **Paquete de pruebas fijas** que sustituye lo que promptfoo no puede generar sin
  red (sustitución de instrucciones con un token, inyección indirecta con el texto malicioso en `vars.contexto`,
  exfiltración por Markdown, fuga entre sesiones, extracción del system prompt); BOLA y BFLA van en
  `custom_tests`.
- **Síntesis** por plugin (`H5-PROMPTFOO-<plugin>`): tasa de fallos, severidad (escalera de H4 con muestra mínima 3,
  suben fugas, autorización y salida peligrosa; suelo MEDIA para un fallo determinista de fuga o autorización),
  estado `potencial` si solo falló el juez, campo `juez` (determinista, LLM local o mixto), OWASP 2025 (ATLAS y
  NIST solo donde coinciden con H4), hasta dos ejemplos saneados, las pruebas con error aparte y una sección
  `## Evaluación del comportamiento del chatbot (promptfoo)` en el informe. `H5-PROMPTFOO-RESUMEN`,
  `-PARCIAL`, `-TIMEOUT`, `-INTERRUMPIDO`, `-ERROR`, `-SIN-RESPUESTA`.
- **Node.js y promptfoo** en el catálogo de instalación, `--check-tools` y `docs/TOOLS.md` /
  `docs/HERRAMIENTAS.md`: promptfoo 0.126.0 necesita **Node.js >= 22.22** (con uno anterior sale
  `H5-PROMPTFOO-NODE-ANTIGUO`, INFO, y no se ejecuta nada). `Herramienta.version_patron` evita tomar la versión
  de Node por la de promptfoo.
- `redactar` oculta, en el bloque `promptfoo` del objetivo que va al informe, los canarios, el system prompt, la
  configuración pegada y las pruebas propias; `apikey` se trata como clave. `h4_garak.severidad` admite
  `muestra_minima` y `clases_suben` para que H5 reutilice la escalera.
- `ejemplos/target.example.json` con el bloque `promptfoo` y `ejemplos/promptfoo.config.example.json`.
- Pruebas herméticas con un promptfoo falso (`tests/promptfoo_falso.py`) y capturas reales saneadas
  (`tests/fixtures/promptfoo/`). Validado de punta a punta contra un llama.cpp real (Qwen2.5-7B): `gate`,
  `quick`, configuración pegada y servidor caído; ningún destino externo salió de la máquina.
- **Límites:** estrategias iterativas, `{{env.X}}` en cabeceras, `--safe-mode` con aserciones `javascript` y
  `::1` en `NO_PROXY` sin probar; vLLM, `standard`, `full` y un juez mayor sin validar; sin PyYAML la
  configuración pegada debe ser JSON.

## [0.12.1] - 2026-11-21

### Corregido
- **`--list` con `-t`:** ahora respeta `tools.<nombre>.path` del objetivo (como `--check-tools`, con la misma
  detección: `cli._estado_herramienta`); antes marcaba «not installed» herramientas instaladas fuera del `PATH`.
  Sin `-t` sigue mirando solo el `PATH`.
- **Trivy sin base de datos (H3-HOST):** el escaneo offline fallaba con «Trivy terminó con un error · returncode 1».
  Ahora, si el stderr indica que falta la base, da `H3-HOST-SIN-BASE` (INFO, sin concluir) con cómo poblarla
  (`trivy image --download-db-only`, con red). Cualquier otro error sigue siendo `H3-HOST-ERROR`.
- **ssh-audit sin servicio SSH (H3-SSH):** «cannot connect to…» ya no se informa como salida ilegible: da
  `H3-SSH-SIN-SERVICIO` (INFO, sin concluir). Una salida realmente ilegible sigue dando `H3-SSH-ERROR`.
- **garak con el servidor parado (H4-GARAK):** con la configuración automática, antes de lanzar garak se hace
  una petición de vida (`GET <uri>models`, 3 s); si no responde, `H4-GARAK-ENDPOINT-NO-RESPONDE` (INFO) y no se
  lanza el barrido. Con `generator_options` propios no se sondea (la URI real puede ser otra): se respeta lo declarado.

## [0.12.0] - 2026-11-17

### Añadido: alias de los hitos
- Cada hito tiene un alias inspirado en los *alters* de la serie *Mr. Robot* (H0 `Mastermind`, H1
  `Real_Elliot`, H2 `The_Voyeur`, H3 `Magda`, H4 `fsociety`, H5 `White_Rose`, H6 `Young_Elliot`, H7
  `Mr_Robot`). Los identificadores del código y del informe **no cambian**: el alias es solo una etiqueta.
- `mrrobotia --list` muestra el hito y el alias de cada escaneo (`garak  H4 · fsociety  [H4-GARAK]`).
  Fuente única: `nucleo.ALIAS_HITOS`; cada módulo declara su `hito` (integridad = H1; configuración, que se
  integra en H2, = H2). El informe no cambia.
- `README.md`, `README.es.md` (tabla de hitos con alias y H7, y apartado de origen) y el manual Word.

## [0.11.1] - 2026-11-17

### Corregido
- **H4 con `-o` relativo:** la carpeta de salida de garak se pasaba relativa, garak ignoraba los
  `XDG_*` relativos (como manda la especificación XDG) y escribía su informe y su registro en
  `~/.local/share/garak`; MRRobotIA decía entonces que «garak terminó sin completar el barrido» aunque
  había acabado bien. Ahora la carpeta se resuelve siempre a ruta absoluta.

## [0.11.0] - 2026-11-17

### Añadido: `--check-tools` y guía de instalación de las herramientas externas
- **Decisión:** MRRobotIA **no instala nada por su cuenta** (es una herramienta de seguridad y descargar
  binarios sola sería un riesgo de cadena de suministro; además, «orquestar, no reinventar»). Lo que hace
  es comprobar y decir cómo.
- **`mrrobotia --check-tools [-t objetivo.json] [--os windows|linux|macos]`**: no necesita objetivo ni
  red. Para cada herramienta (Julius, ssh-audit, Trivy, garak) muestra los escaneos que la usan, si está
  (ruta, de dónde sale y versión), la versión mínima y la fijada, la forma exacta de instalarla en el
  sistema (versión fijada y suma SHA-256 comprobada cuando el proyecto la publica), dónde deja datos o
  cachés y cómo apuntar MRRobotIA a ella. Con `-t` respeta `tools.<nombre>.path` (mecanismo que ya
  existía); `--os` enseña las instrucciones de otro sistema.
- **Una sola fuente de verdad:** nuevo `instalacion.py` con el catálogo de instalación. El hallazgo INFO
  de herramienta ausente (`*-NO-INSTALADA`, `H2-ID-JULIUS-NO-INSTALADA`, `H3-SSH-NO-AUDIT`) y
  `--check-tools` salen de él, y `docs/TOOLS.md` y `docs/HERRAMIENTAS.md` se generan de él (una prueba
  comprueba que cada orden del catálogo está en las dos guías). Los módulos ya no llevan su propio
  texto de instalación (`Herramienta.instalar_con` queda solo como reserva); la versión fijada y la
  mínima exigida viven en la `Herramienta` (`fijada`, `exigida`).
- **El INFO de herramienta ausente** ahora da la forma recomendada del sistema actual y recuerda
  `tools.<nombre>.path` y `--check-tools`.
- **Guía pública** `docs/TOOLS.md` (inglés) y `docs/HERRAMIENTAS.md` (español), enlazadas desde los README:
  una sección por herramienta con para qué se usa, instalación aislada por sistema operativo,
  verificación, cachés (la base de Trivy pesa unos 134 MB de descarga y 1,7 GB descomprimida) y cómo
  apuntar MRRobotIA. promptfoo (H5) y DeepEval (H6) figuran como «próximamente».

### Corregido
- **ssh-audit: la versión no se leía.** ssh-audit no acepta `--version`, así que la traza
  `H3-SSH-AUDIT` salía siempre con versión «desconocida». Ahora se consulta con `-h`, cuya cabecera
  lleva la versión (comprobado con la 3.9.0 real).

### Validado en real (Windows 11)
- **Trivy 0.76.2** instalado siguiendo la guía (con la suma SHA-256 comprobada) y **H3 `vulns` ejecutado
  de punta a punta** contra carpetas reales de solo lectura (este repositorio y otro del laboratorio: sin
  hallazgos) y contra una carpeta de prueba con dependencias antiguas (18 hallazgos reales, 2 críticos y
  2 altos, interpretados correctamente). Hasta ahora solo había salidas simuladas.
- **ssh-audit 3.9.0** instalado en un entorno virtual propio y detectado con su versión. **El escaneo real
  de ssh-audit sigue pendiente:** no hay `sshd` local ni se escanea ningún servidor ajeno.
- Las órdenes de Windows de la guía se han ejecutado de verdad. Las de Linux y macOS están escritas a partir
  de la documentación oficial y de las páginas de versiones de cada proyecto, **sin ejecutar** en esos sistemas.

## [0.10.0] - 2026-11-17

### Añadido: H4, barrido del endpoint con garak (etiqueta `garak`)
- **Módulo `H4-GARAK`** (`-s garak -a`, con `allow_active`): ejecuta garak (>= 0.17.0, probado con la
  0.17.1) por `subprocess`, sin shell y sin nada del objetivo en la línea de órdenes, y **sintetiza su
  `report.jsonl` y su `hitlog.jsonl` en el informe**: una fila por sonda con fallos (tasa de éxito del
  ataque, severidad, marcos OWASP 2025 / ATLAS / NIST) y la sección `## Barrido garak (H4)` con hasta
  dos ejemplos truncados y saneados por sonda. Sustituye al *prober* propio anterior.
- **Fuera de `all`:** se pide con `-s garak` (o `-s all,garak`). `-x` y `-l` lo respetan.
- **Cualquier chatbot:** el contenido de un `garak-config.json` (generador REST, OpenAI-compatible...,
  o una configuración completa con `plugins`) se pega en `garak.generator_options`. Con un servidor
  llama.cpp o vLLM identificado y sin `generator_options`, la configuración se construye sola
  (`<url>/v1/`, `stop: []`, `suppressed_params: ["n"]`). Presets `quick` (medido, unos 4-6 min con un
  7B), `standard` y `full` (duración estimada, sin medir) o sondas propias con `probes`.
- **Claves:** solo por variable de entorno (`api_key_env`); llegan a garak en el entorno de su proceso.
  Una clave en claro en `generator_options` se rechaza sin ejecutar (`H4-GARAK-CLAVE-EN-CLARO`).
- **Núcleo (todo con valores por defecto que no cambian a los demás módulos):** `Modulo.en_all`,
  `Modulo.directorio_salida` (`<prefijo de -o>_<etiqueta>`), `Hallazgo.detalle` (opcional, fuera del
  JSON si es `None`), `nucleo.redactar()` (el informe JSON enmascara `api_key`, `key`, `token`,
  `secret`, `password`, `passphrase`, `client_key*`, los valores de `headers` y oculta las plantillas
  `req_template*`), `herramientas.detectar(env=)` y `Herramienta.aislar_xdg` (la consulta de versión de
  garak no crea carpetas en `~`), y `herramientas.ejecutar(salida=)`: ejecución larga con la salida a
  fichero que, al agotarse el tiempo o con Ctrl-C, mata el árbol de procesos.
- **Privacidad:** garak escribe en las carpetas XDG con la salida de MRRobotIA (`<prefijo>_garak/home/`),
  nunca en el directorio personal; `offline` (por defecto) impide las descargas de Hugging Face y deja
  fuera, avisándolo, las sondas cuyo detector las necesita. `keep_raw` (por defecto `true`) conserva
  `raw/`, que contiene ataques y respuestas **sin filtrar**: el informe lo avisa.
- **Pruebas:** hermético (`tests/garak_falso.py` y capturas reales saneadas en `tests/fixtures/garak/`).
  Validado contra un `llama-server` real (7B): configuración automática, `garak-config.json` REST pegado
  y tiempo agotado con informe parcial y muerte del árbol de procesos. **vLLM: solo pruebas herméticas,
  sin validar en real.**

## [0.9.1] - 2026-11-17

### Corregido (rarezas al probar en Windows con un llama-server real)
- **BOM en el objetivo:** el JSON del objetivo, el manifiesto de M2 y los JSON de configuración de M3 se leen con
  `utf-8-sig`; un fichero escrito con `Set-Content -Encoding UTF8` de PowerShell 5.1 ya no da «not valid JSON».
- **llama.cpp sin versión:** si ni `/props` ni `/build.json` dan la build (p. ej. `--api-key` con `--no-webui`),
  H2-BUILD ya no se titula «detectada»: pasa a «No se ha podido determinar la build» y queda «sin concluir».
- **`--server` forzado:** el hallazgo dice «Servidor forzado con --server» en lugar de «identificado»; si lo detectado lo contradice sigue saliendo H2-ID-CONFLICTO.
- **M2:** el hallazgo de hash distinto ya no dice «no coincide con el manifiesto» si el hash esperado venía en
  línea en el objetivo: «no coincide con el hash esperado» y la evidencia nombra su fuente.

## [0.9.0] - 2026-11-16

### Corregido (tras contrastar el perfil de vLLM con un vLLM 0.33.0 real en CPU)
- **Servidor fantasma:** los procesos que cuelgan del servidor (`VLLM::EngineCore`, `VLLM::Worker`...) ya no se
  cuentan como otro servidor ni sus puertos efímeros como puertos inesperados en H3. Se agrupa por árbol de
  procesos (ahora se lee el proceso padre en Linux y Windows) y los puertos de esos hijos son canales internos.
- **CORS:** una comprobación previa respondida con 400 «Disallowed CORS origin» es una respuesta concluyente
  («no admite orígenes externos»), no «sin concluir».
- **Frontend Rust de vLLM** (`owned_by: vllm-frontend-rs`): `/v1/models` sin clave ya cuenta como autenticación
  abierta y confirma H2-HOST.
- **Versión en modo pasivo:** se lee de `vllm-*.dist-info/METADATA` del entorno virtual del proceso (solo
  ficheros locales, sin red).
- **H2-CONTROL-SIN-CLAVE:** `/scale_elastic_ep` existe en todos los modos y `--api-key` no la protege, pero solo
  reescala un motor con data parallel elástico; sola pasa a informativa. Las demás rutas de control, igual.
- **Modo desarrollo:** también se comprueba `/pause` (404 sin el modo, 405 con él).
- **Evidencia de enlace:** H2-BIND y H2-ID dicen la dirección real de escucha de la tabla de puertos.
- **H3 en WSL:** el resolvedor DNS que WSL2 pone en 10.255.255.254:53 deja de salir como puerto inesperado
  (solo en WSL, sin proceso visible y sin otra dirección en ese puerto).
- `/ping` figura entre las rutas públicas conocidas del perfil.
- El texto de ayuda del comando decía que las claves del objetivo estaban en español; están en inglés desde la 0.8.0.

### Documentación
- HITOS y READMEs: vLLM validado contra un vLLM 0.33.0 real en CPU; sin validar GPU, generación, Trivy y ssh-audit.
- Propuesta sin implementar: usar el número de rutas de OpenAPI como señal de modo (varía con la versión y las opciones).

## [0.8.0] - 2026-11-15

### Cambiado (ruptura: fichero y claves renombrados, sin compatibilidad con los antiguos)
- **El fichero de objetivo pasa a llamarse `target.json`** (el ejemplo, `ejemplos/target.example.json`)
  y **todas sus claves pasan a inglés**. Un `objetivo.json` antiguo ya no sirve: hay que
  renombrarlo y traducir las claves según la tabla. Los hallazgos del informe y los mensajes de
  los módulos siguen en español.

| Antes | Ahora |
|---|---|
| `nombre` | `name` |
| `servidor` | `server` |
| `permitir_activos` | `allow_active` |
| `autorizacion` | `authorization` |
| `autorizacion.tengo_autorizacion` | `authorization.authorized` |
| `autorizacion.autorizado_por` | `authorization.authorized_by` |
| `autorizacion.ambito` | `authorization.scope` |
| `autorizacion.fecha` | `authorization.date` |
| `autorizacion.confirmo_no_local` | `authorization.confirm_non_local` |
| `exposicion` | `exposure` |
| `exposicion.puerto` | `exposure.port` |
| `exposicion.bind_esperado` | `exposure.expected_bind` |
| `exposicion.proxy_autenticador` | `exposure.auth_proxy` |
| `exposicion.api_key_esperada` | `exposure.api_key_expected` |
| `manifiesto` | `manifest` |
| `manifiesto_firmado` | `manifest_signed` |
| `artefactos[].ruta` | `artifacts[].path` |
| `usuarios` | `users` |
| `auditoria` | `audit` |
| `dir_logs` | `logs_dir` |
| `ssh.puerto` | `ssh.port` |
| `puertos.esperados` | `ports.expected` |
| `puertos.extra_peligrosos` | `ports.extra_dangerous` |
| `host_trivy` | `trivy_host` |
| `host_trivy.ruta` | `trivy_host.path` |
| `host_trivy.escaneres` | `trivy_host.scanners` |
| `host_trivy.severidad` | `trivy_host.severity` |
| `herramientas` | `tools` |
| `herramientas.<nombre>.ruta` | `tools.<name>.path` |

Sin cambios: `endpoint`, `host`, `app_dir`, `ssh.sshd_config`, `artifacts[].sha256`,
`tools.<name>.timeout` y `tools.<name>.cache_dir`.

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
