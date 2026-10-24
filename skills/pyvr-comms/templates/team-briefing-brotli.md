# Team briefing: HTTP2Shell (Brotli)

## EN
**Subject:** Action needed: upgrade Brotli in our Python apps (HTTP2Shell)

Team,

A memory-corruption bug in Google's Brotli decoder (CVE-2026-111497, "HTTP2Shell") also
affects Python: the `Brotli` and `brotlicffi` packages bundle that decoder. We rarely
import them directly, but requests/urllib3, aiohttp, httpx and Scrapy decode Brotli
automatically once installed, so any service that fetches URLs we do not control
(webhooks, link previews, crawlers) is in scope. No confirmed attacks so far.

Fixed: Brotli 1.2.1, brotlicffi 1.2.1.0.

What to do:
1. Run the scanner: `python3 pyvuln-scan.py --local --venvs ~/code --project ~/code -o pyvuln`
2. Upgrade each environment it flags and re-lock (`uv lock --upgrade-package brotli`, `poetry update brotli`).
3. Where we declare `urllib3[brotli]`, `httpx[brotli]` or `aiohttp[speedups]`, add `Brotli>=1.2.1`.
4. Rebuild images with `--pull`. Servers using `python3-brotli`: apply the OS update.
5. If Brotli is optional for a service, uninstalling it is an acceptable fix.

Questions: {{owner}}. Deadline: {{deadline}}.

## ES
**Asunto:** Acción requerida: actualizar Brotli en nuestras apps de Python (HTTP2Shell)

Equipo:

Una falla de corrupción de memoria en el decodificador Brotli de Google (CVE-2026-111497,
"HTTP2Shell") también afecta a Python: los paquetes `Brotli` y `brotlicffi` incluyen ese
decodificador. Casi nunca los importamos directamente, pero requests/urllib3, aiohttp,
httpx y Scrapy decodifican Brotli automáticamente si está instalado, así que cualquier
servicio que consulte URLs que no controlamos (webhooks, vistas previas de enlaces,
crawlers) está en riesgo. No se conocen ataques confirmados por ahora.

Corregido en: Brotli 1.2.1, brotlicffi 1.2.1.0.

Qué hacer:
1. Correr el escáner: `python3 pyvuln-scan.py --local --venvs ~/code --project ~/code -o pyvuln`
2. Actualizar cada entorno marcado y regenerar los lockfiles (`uv lock --upgrade-package brotli`, `poetry update brotli`).
3. Donde declaremos `urllib3[brotli]`, `httpx[brotli]` o `aiohttp[speedups]`, agregar `Brotli>=1.2.1`.
4. Reconstruir las imágenes con `--pull`. Servidores con `python3-brotli`: aplicar la actualización del sistema.
5. Si Brotli es opcional para un servicio, desinstalarlo es una solución válida.

Preguntas: {{owner}}. Fecha límite: {{deadline}}.
