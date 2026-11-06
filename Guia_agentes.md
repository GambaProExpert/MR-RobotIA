# Guía de agentes — MRRobot (rediseño por capas)

Vamos a cambiar el enfoque de la herramienta **MRRobot** a algo que por sí solo pueda hacer algo como lo que llevamos hecho (M1, M2, M3 y M4), pero que estas funcionalidades y las demás que vayamos haciendo se vean apoyadas en otras herramientas ya hechas. O sea, que MRRobot hará uso de las que sea posible utilizar para realizar una auditoría de servidor local de IA; bueno, la auditoría no la va a hacer, pero los datos sí que los sacará. No hay que utilizarlas todas: yo solo utilizaría las necesarias para cubrir:

- Los *prompt injections* con **promptfoo**.
- El escáner de inventario y exposición.
- Las vulnerabilidades del Host.
- La integridad de archivos con SHA256, que ya estaba hecho.
- **garak** para el barrido del endpoint.
- **DeepEval** para asegurarnos de que los prompts y las salidas no salgan de la red (**MUY IMPORTANTE**).
- Y, si eso, algo de herramientas MCP, pero eso más tarde; no le hagas caso ahora.

Mira el contenido dividido por capas e investiga si fuese posible implementarlo:

> **Ojo:** vamos a dividir cada una de estas herramientas de MRRobot en un hito. Un hito puede durar mucho, así que quiero que investigues exhaustivamente y declares bien todo para que la herramienta resulte útil.

---

## Capa 1: la infraestructura que sirve el modelo

Aquí el riesgo real no es la IA, es el servidor expuesto. Ollama escucha en `127.0.0.1:11434` por defecto y **no tiene mecanismo de API key**; vLLM arranca en todas las interfaces si no pasas `--host`, y su `--api-key` solo cubre las rutas `/v1`, `/v2`, `/inference` y `/cohere`, dejando sin autenticación `/invocations`, `/pause`, `/update_weights`, `/metrics` o `/tokenize`. Hay CVEs concretos que justifican auditar versiones: **CVE-2024-37032** en Ollama (corregido en 0.1.34) y **CVE-2025-32444** en vLLM, con CVSS 10.0. *(praesidia)*

### Herramientas útiles en esta capa

- **Escáner de inventario y exposición**: barrido de rangos internos en busca de los puertos por defecto (`11434` Ollama, `8080` llama.cpp, `8000` vLLM, `1234` LM Studio; en nuestro caso solo implementaremos para **llama.cpp**) y comprobación, desde un segmento no confiable, de que gestión, métricas y puertos de clúster son inalcanzables. *(nhimg)*
- **Greenbone/OpenVAS, Nessus o Trivy**: vulnerabilidades de host, contenedores, IaC y secretos filtrados en el repositorio del despliegue.
- **Julius (Praetorian) y AI-Infra-Guard (Tencent)**: fingerprinting de plataformas de serving, gateways, MCP y RAG, con enumeración de modelos expuestos y correlación contra CVEs conocidos.
- **Geiger, ModelAudit y Sandbox Probe**: inventario de instalaciones de agentes y configuraciones MCP, escaneo estático de artefactos de modelo (pickle, metadatos) y medición de capacidades efectivas del sandbox frente al host.

La auditoría aquí es sobre todo de **configuración**: bind a loopback o interfaz privada, proxy autenticador delante, allowlist de rutas, origen de navegador restringido en Ollama (evita *DNS rebinding*), usuario no root y sin claves de proveedor en el host de inferencia. *(praesidia)*

---

## Capa 2: el modelo y la aplicación LLM

Para esto sí hay herramientas específicas, todas ejecutables en local contra tu propio endpoint:

| Herramienta | Enfoque | Cuándo usarla |
| --- | --- | --- |
| **garak** (NVIDIA, Apache 2.0) | Escáner de vulnerabilidades: 191 sondas en 42 módulos, detectores integrados, informe HTML/JSONL | Barrido rápido y amplio de un modelo o endpoint; soporta Ollama, llama.cpp, NIM y REST *(agentopsguide)* |
| **promptfoo** | Red team + evals en YAML, plugins de agencia excesiva, BOLA/BFLA, MCP, inyección indirecta, fuga entre sesiones | Integrarlo como *gate* en CI en cada cambio de prompt, modelo o herramienta *(cleanissue)* |
| **DeepTeam / DeepEval** | Red teaming local sobre DeepEval, con juez local vía `deepeval set-ollama` | Cuando prompts y salidas no pueden salir de la red |

Un dato útil para calibrar expectativas: un escaneo de 256 prompts con garak contra `llama3.2:1b` servido por Ollama dio un **39,84 % de éxito en inyección de prompt** (IC 95 %: 33,59–45,70), con falsos positivos del detector incluidos en la metodología. Es decir, el modelo pequeño local no es un entorno seguro por defecto. *(github)*

---

## Capa 3: agentes, MCP y superficie de herramientas

Si tu infraestructura local incluye agentes con acceso a ficheros, shell o servidores MCP, añade:

- **agentic-radar**: escaneo de flujos agénticos para encontrar vulnerabilidades; ejecutable en CI.
- **Ship Safe / API Relay Audit**: revisión de configuraciones de agente y auditoría de relays o proxies LLM (inyección, sustitución de modelo, truncado de contexto). *(theinjection.dev)*
