*Read this in [English](README.md).*

# MRRobotIA — auditor de postura defensiva de LLM auto alojados

Herramienta de **auditoría defensiva** (hardening) para servidores LLM auto alojados. Primero
**identifica** con qué se está tratando (servidor, versión, cómo se arrancó y en qué sistema),
adapta las comprobaciones a lo que ha encontrado y **normaliza todo en un informe único** con
severidades y referencias a OWASP LLM Top 10 2025, MITRE ATLAS y NIST AI 600-1. Cuando es útil,
**orquesta herramientas ya consolidadas** (Julius, ssh-audit, Trivy, garak, promptfoo y DeepTeam) de forma local y offline: «la auditoría no la hace MRRobotIA; los datos
sí los saca». La hoja de ruta está en [HITOS.md](HITOS.md).

## Qué revisa

| Hito · alias | Escaneo (`-s`) | Qué mira | Tipo | En `all` |
|---|---|---|---|---|
| H1 · `Real_Elliot` | `integrity` | SHA-256 de modelos, adaptadores y bases vectoriales | Pasivo | Sí |
| H2 · `The_Voyeur` | `id`, `config`, `exposure`, `startup`, `cve` | Servidor y versión, configuración de la aplicación, enlace, autenticación, opciones de arranque, avisos de seguridad | Híbrido | Sí |
| H3 · `Magda` | `ssh`, `ports`, `vulns` | Endurecimiento de SSH, puertos inesperados del host, vulnerabilidades y secretos del disco (Trivy) | Híbrido | Sí |
| H4 · `fsociety` | `garak` | Barrido del modelo con garak: jailbreak, inyección de prompt, fuga del system prompt | Activo | No |
| H5 · `White_Rose` | `promptfoo`, `deepteam` | Comportamiento del chatbot (fuga del system prompt, inyección, BOLA/BFLA), con juez local y la red bloqueada | Activo | No |
| H6 · `Young_Elliot` | `egress` | ¿Salen datos de la red? Canales de salida y conexiones del servidor | Híbrido | Sí (sin `-a`, solo la parte estática) |
| H7 · `Mr_Robot` | — | Simulación de ataques con verificación de detección y recuperación (pendiente) | — | — |

Los escaneos **pasivos** solo observan (disco, procesos, tabla de puertos); los **híbridos** además
hablan con el servicio, sin modificar nada, si el sondeo activo está autorizado (`-a` y `allow_active: true`
en el objetivo); los **activos** envían ataques al modelo y no entran en `all`: se piden con `-s <etiqueta> -a`.
Detalle de cada uno en la guía:
[H4](docs/GUIA.md#h4-barrido-con-garak--s-garak),
[H5](docs/GUIA.md#h5-evaluación-del-chatbot-con-promptfoo--s-promptfoo),
[H5, segundo motor](docs/GUIA.md#h5-segundo-motor-deepteam--s-deepteam) y
[H6](docs/GUIA.md#h6-salen-datos-de-la-red--s-egress).

## Estado de la validación

- **llama.cpp**: perfil completo probado contra un `llama-server` real (build b11583).
- **vLLM**: validado contra un vLLM 0.33.0 real en CPU (solo peticiones de lectura); sin validar en GPU ni con generación.
- **garak, promptfoo y DeepTeam**: ejecutados de punta a punta contra un llama.cpp real; en vLLM, sin validar.
- **H6 (`egress`)**: validado contra un `llama-server` real y un vLLM real en CPU; ve destinos, no contenido (TLS).
- **Trivy**: validado en real. **ssh-audit**: instalado y detectado; su escaneo real sigue pendiente.
- **Sistemas operativos**: Windows 11 y Ubuntu 24.04 (WSL2).
- **Un juez local pequeño no es fiable**: la señal de confianza son los canarios.

La tabla completa está en la [guía](docs/GUIA.md#estado-de-la-validación).

## Instalación
Requiere Python >= 3.10. Desde la raíz del proyecto (donde está `pyproject.toml`):
```
pip install -e .
```
Esto instala el paquete `mrrobotia` y el comando de consola `mrrobotia`. Para ejecutar las
pruebas, instala además las dependencias de desarrollo y lanza `pytest`:
```
pip install -e ".[dev]"
pytest
```
El paquete solo usa la biblioteca estándar: no añade dependencias en tiempo de ejecución.
Las herramientas externas (Julius, ssh-audit, Trivy, garak, Node.js, promptfoo y DeepTeam) son
opcionales y se instalan aparte; si falta una, el informe lo dice y explica cómo instalarla.
MRRobotIA nunca instala nada por su cuenta. `mrrobotia --check-tools` muestra qué escaneos usan
cada herramienta, si está instalada y cómo instalarla en tu sistema; la guía completa, con
versiones fijadas y verificación de sumas, es [docs/HERRAMIENTAS.md](docs/HERRAMIENTAS.md).
Para garak, ver [H4](docs/GUIA.md#h4-barrido-con-garak--s-garak); para promptfoo (necesita
Node.js 22.22 o superior), [H5](docs/GUIA.md#h5-evaluación-del-chatbot-con-promptfoo--s-promptfoo);
para DeepTeam (un entorno virtual de Python),
[H5, segundo motor](docs/GUIA.md#h5-segundo-motor-deepteam--s-deepteam).

## Inicio rápido
Copia el objetivo de ejemplo (en Windows: `copy ejemplos\target.example.json target.json`):
```
cp ejemplos/target.example.json target.json
```
Edita `target.json`: pon `authorized` a `true` **solo si tienes permiso** y rellena
`authorized_by`, `scope` y `date`. Después lanza un escaneo y lee el informe:
```
mrrobotia -t target.json -o informes/hoy
```
Salen `informes/hoy.md` (legible) e `informes/hoy.json`. Para ver qué escaneos hay, `mrrobotia -l`.
Otras combinaciones:
```
mrrobotia -t target.json -s passive          # solo observa, no habla con el servicio
mrrobotia -t target.json -s server -x cve    # el servidor LLM, sin el escaneo de avisos
mrrobotia -t target.json -a                  # permite además el sondeo por red
mrrobotia -t target.json -s promptfoo -a     # evalúa el chatbot con promptfoo (H5; activo, no entra en all)
mrrobotia -t target.json -s egress           # ¿salen datos de la red? (H6; -a añade tráfico de canario)
```
Las **opciones del comando, las etiquetas y el fichero de objetivo (`target.json` y todas sus
claves) están en inglés; el informe y los mensajes de los módulos siguen en español** por ahora.

## Documentación
- [Guía de uso](docs/GUIA.md): estado de la validación, fichero de objetivo, opciones del comando,
  escaneos y grupos, H4, H5 (promptfoo y DeepTeam), H6, modelo de amenazas, estructura del
  proyecto, hitos y alias.
- [Guía de herramientas externas](docs/HERRAMIENTAS.md): cómo instalar y verificar cada una.
- [HITOS.md](HITOS.md): hoja de ruta.
- [CHANGELOG.md](CHANGELOG.md): cambios por versión.
- [LICENSE](LICENSE): licencia.

## Principios
- **Autorización explícita.** El objetivo declara que tienes permiso. Sin
  `authorization.authorized = true`, la herramienta no corre. Un host no local exige
  confirmación aparte (`confirm_non_local`). Es el equivalente al consentimiento de un pentest.
- **Lectura por defecto.** Los escaneos pasivos solo observan. El sondeo por red exige
  `--active` y `allow_active: true` en el objetivo.
- **Solo tu infraestructura o con permiso escrito.** No escanea ni prueba sistemas de terceros.
- **Nada sensible en el informe.** Las líneas de órdenes se reducen a una lista blanca de
  opciones; las claves, los tokens y las rutas absolutas de modelos no se guardan, solo su presencia.
- **Orquestar, no reinventar.** Las herramientas externas se ejecutan con `subprocess`, con la
  orden como lista y sin `shell=True`; si no están instaladas, se informa y no se da la
  comprobación por hecha.

## No incluye
- Extracción de secretos de la memoria de procesos.
- Generación de carga para agotar recursos (DoS).
- Escaneo o prueba de sistemas ajenos.
