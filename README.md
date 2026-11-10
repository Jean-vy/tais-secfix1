# secfix — SAST + LLM en GitHub Actions para detectar, reparar y validar vulnerabilidades

Prototipo del Hito 2 (TAIS, UNSA). En cada pull request, `secfix`:

1. calcula las líneas cambiadas del PR;
2. ejecuta **Semgrep CE** con reglas propias para **CWE-89 (SQLi)**, **CWE-79 (XSS)** y **CWE-434 (carga insegura de archivos)**;
3. pide a un **LLM** (cualquier API compatible con OpenAI; por defecto Groq, que tiene plan gratuito) que clasifique cada hallazgo como verdadero o falso positivo;
4. para los verdaderos positivos, pide al LLM la función corregida;
5. **valida** cada parche de forma determinista:
   - **V1** compila;
   - **V2** Semgrep ya no reporta el hallazgo y no aparecen otros;
   - **V3** los tests que pasaban siguen pasando;
   - **V4** el test de explotación que fallaba ahora pasa;
   
   Si falla, reintenta una vez con el error como retroalimentación;
6. publica en el PR una review con **sugerencias aplicables con "Commit suggestion"** y un resumen, y **falla el check** mientras queden vulnerabilidades confirmadas. Con la protección de rama activada, eso bloquea el merge.

Al aceptar las sugerencias se crea un commit nuevo y el workflow vuelve a correr. Si ya no quedan verdaderos positivos, el check pasa a verde.

## Estructura

```
action.yml                 GitHub Action compuesta (reutilizable con `uses:`)
secfix/                    motor en Python
  cli.py                   comandos `pr` (Actions) y `scan` (local)
  diff.py                  líneas cambiadas y líneas comentables del PR
  sast.py                  ejecución y normalización de Semgrep
  context.py               recorte de contexto mínimo y aplicación de parches
  llm.py                   cliente LLM compatible con OpenAI, con control de cuota
  triage.py  repair.py     etapas LLM; prompts en secfix/prompts/
  validate.py              validación V1–V4
  pipeline.py              orquestación
  report.py                review con sugerencias, resumen, métricas JSON
rules/                     reglas Semgrep (sqli.yml, xss.yml, upload.yml)
lab/                       app Flask de laboratorio + harness de pruebas funcionales y de explotación
demo/                      módulo vulnerable para el PR de demostración
experiment/                24 casos con ground truth, runner C0 vs C1 y análisis
tests/                     pruebas del motor con LLM simulado
.github/workflows/         secfix.yml (PR), ci.yml (pruebas), experiment.yml (experimento)
```

## Puesta en marcha en GitHub (una vez)

1. Crea un repositorio (público o privado) y sube este contenido a `main`.
2. **Settings → Actions → General → Workflow permissions**: elige *Read and write permissions*.
3. **Settings → Branches → Add branch protection rule** para `main`:
   - Marca *Require a pull request before merging*.
   - Marca *Require status checks to pass*.
   - Agrega el check **`secfix`**. Aparece en la lista después de la primera ejecución.
4. **API key del LLM.** GitHub Models se retiró el 30/07/2026, así que se usa cualquier API compatible con OpenAI. Por defecto es **Groq**, que tiene plan gratuito:
   - Crea una key en <https://console.groq.com/keys>.
   - Guárdala en **Settings → Secrets and variables → Actions → New repository secret** con el nombre `LLM_API_KEY`.
   - Para usar otro proveedor, crea en la pestaña *Variables* `LLM_ENDPOINT` (la URL de `/chat/completions`) y `LLM_MODEL`. Por ejemplo, para Gemini: `https://generativelanguage.googleapis.com/v1beta/openai/chat/completions` con `gemini-2.5-flash`.

## PR de demostración (para las capturas del informe)

```bash
git checkout -b demo-perfil
cp demo/perfil.py lab/routes/perfil.py
tail -n +2 demo/perfil_specs.yaml >> lab/specs.yaml
git add -A && git commit -m "Agrega módulo de perfil"
git push -u origin demo-perfil
```

Abre el PR hacia `main`. En unos minutos deberías ver:
- 3 comentarios en línea con sugerencias validadas: SQLi, XSS y upload;
- un resumen con el hallazgo descartado como falso positivo (la ruta `resumen`, cuyos valores son `int`);
- el check `secfix` en rojo.

Pulsa **Commit suggestion** en cada comentario (o *Add suggestion to batch* → *Commit suggestions*). El workflow vuelve a correr y el check queda en verde.

## Uso local

```bash
pip install -r requirements.txt
python -m pytest -q tests lab/tests            # motor (LLM simulado) + laboratorio

# Solo Semgrep (sin LLM):
python -m secfix.cli scan --mode sast-only demo/perfil.py

# Semgrep + LLM: necesitas la API key del proveedor (por defecto, Groq)
export SECFIX_LLM_TOKEN=gsk_...
python -m secfix.cli scan --test-cmd "python -m pytest -q lab/tests" lab/routes/perfil.py
```

## Experimento (Hito 2)

- **Casos:** `experiment/cases.yaml` define 24 casos, con 8 por CWE: 5 vulnerables y 3 "seguros pero sospechosos". Cada caso tiene una petición legítima y un ataque.
- **Configuraciones (variable independiente):**
  - **C0:** Semgrep solo.
  - **C1:** Semgrep + LLM (triage + reparación + validación V1–V4).
  - **C1b** (opcional): igual que C1, pero sin V4 al validar. Sirve para medir cuánto aporta la prueba de explotación.
- **Métricas (variables dependientes):**
  - precisión, recall, F1 y exactitud;
  - reducción de falsos positivos;
  - tasa de reparación;
  - parches que rompen la funcionalidad;
  - tiempo, llamadas y tokens por caso.

  La reparación siempre se mide aparte: se aplican los parches aceptados y se vuelve a lanzar el ataque.

**Opción A — en GitHub (usa el secret `LLM_API_KEY`):** ve a *Actions → experiment → Run workflow*, con `configs = C0,C1` y `reps = 1`. Descarga el artefacto `resultados-experimento-r0`. Para la segunda repetición usa `rep_offset = 1`, y así sucesivamente. Luego copia todos los `runs_r*.jsonl` a `experiment/results/` y ejecuta `python experiment/analyze.py`.

**Opción B — local:**

```bash
export SECFIX_LLM_TOKEN=gsk_...           # API key del LLM
python experiment/run_experiment.py --configs C0,C1 --reps 3
python experiment/analyze.py              # genera summary.md, summary.csv y metricas.png
```

**Cuota gratuita:** cada proveedor tiene límites propios por minuto y por día; revísalos en su consola. Una repetición de C1 usa unas 50–60 llamadas. El cliente espera 4,5 s entre llamadas y reintenta los 429. Si se agota la cuota diaria, el runner se detiene: vuelve a ejecutarlo al día siguiente y continúa donde se quedó. También pueden repartir las repeticiones entre las cuentas de los integrantes, cada una con su token y su `--rep-offset`.

**Línea base ya medida (C0, determinista):** precisión 62,5 %, recall 100 %, F1 76,9 %, 9 falsos positivos y 0 % de reparación.

## Decisiones de diseño y limitaciones

- **Unidad de reparación:** la función que contiene el hallazgo. Varios hallazgos en la misma función se reparan juntos, para que las sugerencias no choquen. Los imports nuevos van dentro de la función, para que el parche quepa en una sola sugerencia.
- **Sugerencias fuera del diff:** GitHub solo acepta sugerencias sobre líneas del diff. Si la función no está completa en el diff, el parche se muestra como bloque de código.
- **V3/V4 en un PR:** se comparan con una línea base. Se ejecutan los tests sin parche y con parche: V3 exige que no aparezcan fallas nuevas, y V4 que disminuyan los tests de explotación que fallan.
- **Prompt injection:** el código del PR es entrada no confiable. Por eso:
  - el LLM no tiene herramientas y solo devuelve JSON;
  - la validación determinista decide qué se muestra;
  - se usa `pull_request` (no `pull_request_target`) con permisos mínimos;
  - la decisión final es del desarrollador.
  
  Úsalo solo con PRs del mismo repositorio.
- **Por diseño, el LLM solo filtra hallazgos:** el recall de C1 no puede superar al de C0.
- **Semgrep CE sin sesión** no entrega las trazas de flujo de datos. `secfix` reconstruye una traza simple: las líneas de la función que leen `request.*`.
