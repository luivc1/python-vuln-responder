# Team briefing

## EN
**Subject:** Action needed: upgrade Pillow to 13.0.0 (critical image-handling flaws)

Team,

Pillow 13.0.0 fixes about 40 security issues, two rated critical. Opening or saving a
crafted image can corrupt memory, and with Ghostscript installed an EPS file can run
commands. Every Pillow before 13.0.0 is affected. Apps that handle images from users or
the internet come first.

Catch: Pillow 13.0.0 needs Python 3.11 or newer, and there is no 12.x backport.
Python 3.10 apps must move to a newer Python (3.10 reaches end of life this month).

What to do:
1. Run the scanner: `python3 pyvuln-scan.py --local --venvs ~/code --project ~/code -o pyvuln`
2. Follow the generated fix plan: upgrade each environment, bump pins to `pillow>=13.0.0`, re-lock.
3. Move `FROM python:3.10` images that use Pillow to 3.11+ and rebuild with `--pull`.
4. If you are stuck on 3.10 for now: remove Ghostscript where not needed, restrict
   `Image.open(..., formats=[...])`, and tell {{owner}} the date you can upgrade.

Questions: {{owner}}. Deadline: {{deadline}}.

## ES
**Asunto:** Acción requerida: actualizar Pillow a 13.0.0 (fallas críticas al procesar imágenes)

Equipo:

Pillow 13.0.0 corrige unos 40 problemas de seguridad, dos de ellos críticos. Abrir o
guardar una imagen manipulada puede corromper la memoria, y con Ghostscript instalado un
archivo EPS puede ejecutar comandos. Todas las versiones de Pillow anteriores a 13.0.0
están afectadas. Primero van las apps que procesan imágenes de usuarios o de internet.

Detalle: Pillow 13.0.0 requiere Python 3.11 o más reciente y no hay parche para 12.x.
Las apps en Python 3.10 deben pasar a un Python más nuevo (3.10 llega a fin de soporte este mes).

Qué hacer:
1. Correr el escáner: `python3 pyvuln-scan.py --local --venvs ~/code --project ~/code -o pyvuln`
2. Seguir el plan de corrección: actualizar cada entorno, subir las versiones a `pillow>=13.0.0` y regenerar los lockfiles.
3. Pasar las imágenes `FROM python:3.10` que usan Pillow a 3.11 o más y reconstruirlas con `--pull`.
4. Si por ahora siguen en 3.10: quitar Ghostscript donde no se use, restringir
   `Image.open(..., formats=[...])` y avisar a {{owner}} la fecha en que pueden actualizar.

Preguntas: {{owner}}. Fecha límite: {{deadline}}.
