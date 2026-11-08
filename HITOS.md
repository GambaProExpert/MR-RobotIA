# MRRobotIA — Hitos (roadmap por capas)

> Operativiza [Guia_agentes.md](Guia_agentes.md). Alcance elegido: **LLM + RAG + host**.
> Estado de este documento: **plan**. La investigación exhaustiva por hito se hará con savvy-flow.

## Qué es ahora MRRobotIA

Un **orquestador defensivo**: no reimplementa cada comprobación, sino que **ejecuta herramientas
ya consolidadas** contra un servidor LLM local y **normaliza sus datos** a un informe único
(`Hallazgo` + `Severidad` + marcos OWASP LLM Top 10 2025 · MITRE ATLAS · NIST AI 600-1).
«La auditoría no la hace MRRobotIA; los datos sí los saca.» Cada herramienta = un hito.

### Principios

- **Orquestar, no reinventar.** Si una herramienta no está instalada, MRRobotIA emite un hallazgo
  informativo con cómo instalarla; nunca revienta ni la da por ejecutada.
- **Todo local y offline.** Nada de prompts ni salidas sale de la red (ver H6, *muy importante*).
- **Deny-by-default + doble consentimiento** para módulos activos (ya en el núcleo).
- **Sin dependencias de ejecución nuevas en MRRobotIA**: las herramientas externas se invocan por
  `subprocess` y su salida (JSON/JSONL) se parsea a `Hallazgo`.

## Hitos

| Hito | Capa | Base / herramienta | Qué extrae | Estado |
|---|---|---|---|---|
| **H0 · Núcleo orquestador** | — | código propio | `HerramientaExterna`: detectar (`which`/versión), ejecutar con *timeout*, parsear salida a `Hallazgo`, mapear marcos; config de rutas de herramientas | **hecho** |
| **H1 · Integridad SHA-256** | 1 | código propio (M2) | hashes de modelos/adaptadores/índices frente a manifiesto o `sha256` en línea | **hecho** |
| **H2 · Inventario y exposición** | 1 | código propio | puerto por defecto de **llama.cpp (`:8080`)**; *bind* a loopback vs `0.0.0.0`; sin API key; `/slots` (fuga de prompts), `/props` (ruta del modelo + build), `/v1/models`, `/metrics`, CORS; HTTP sin TLS; usuario del proceso; claves de proveedor en el entorno | **hecho** |
| **H3 · Seguridad del host** | 1 | código propio + **Trivy** | SSH (`sshd_config` CIS + `ssh-audit`), puertos abiertos innecesarios/inseguros (línea base vLLM/llama.cpp), y vulnerabilidades/secretos/config con Trivy. Selector `--escaneo`. | **hecho** |
| **H4 · Barrido del endpoint** | 2 | **garak** (NVIDIA) | barrido amplio del endpoint REST/llama.cpp (sondas de inyección y más) → informe JSONL normalizado | por hacer (reconvierte el M1 propio) |
| **H5 · Prompt injection / evals** | 2 | **promptfoo** | red team + evals en YAML como *gate* de CI: inyección directa e indirecta, fuga entre sesiones, agencia excesiva, BOLA/BFLA | por hacer |
| **H6 · Datos no salen de la red** | 2 | **DeepEval / DeepTeam** | **MUY IMPORTANTE**: comprobar que prompts y salidas no salen de la red; juez local (`deepeval set-ollama`), red teaming offline | por hacer |
| Capa 3 · agentes, MCP, herramientas | 3 | agentic-radar, etc. | superficie de agentes/MCP | **más adelante** (fuera de alcance ahora) |

## Orden propuesto

`H0 → H2 → H3 → H4 → H5 → H6`

- **H0, H2 y H3 no dependen** de instalar garak/promptfoo/DeepEval: son el cimiento y la Capa 1.
- **H4–H6** sí requieren esas herramientas en local; se abordan después del núcleo.

## Qué declara cada hito (a rellenar con savvy-flow)

Para cada hito, la investigación debe fijar: instalación **local y offline**; comando exacto
contra un endpoint **llama.cpp**; formato de salida y su parseo; mapeo a severidad + marcos
(OWASP·ATLAS·NIST); si es módulo **activo** o pasivo; y pruebas sin red ni modelo.

## Estado del repositorio

- Hecho: núcleo (`nucleo.py`), **H1/M2** (`m2_integridad.py`), M3 de configuración (se replantea
  dentro de **H2**).
- Pendiente de reconciliar: `m1_robustez.py` y `datos/probes_base.jsonl` de un worker interrumpido
  por el límite de uso; se integran en **H4** (garak) o se conservan como respaldo offline.
