"""Ejecuta el experimento: C0 (Semgrep solo) vs C1 (Semgrep + LLM).

Configuraciones:
  C0   Semgrep solo. Un caso se predice vulnerable si hay al menos un hallazgo.
  C1   Semgrep + triage LLM + reparación LLM + validación V1–V4.
  C1b  (opcional) igual que C1 pero validando solo V1–V3, sin la prueba de
       explotación. Sirve para medir cuánto aporta V4 y evitar circularidad.

En todas, la reparación final se mide de forma independiente: se aplican los
parches aceptados y se ejecuta el harness (funcional + explotación).

Uso:
  export SECFIX_LLM_TOKEN=...   # API key del LLM (o corre el workflow 'experiment')
  python experiment/run_experiment.py --configs C0,C1 --reps 3
  python experiment/run_experiment.py --configs C0 --reps 1      # sin LLM, para probar

Los resultados se agregan a experiment/results/runs.jsonl. Si se agota la cuota
diaria, vuelve a ejecutar el mismo comando otro día: los casos ya hechos se saltan.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

from secfix.llm import LLMClient, LLMError  # noqa: E402
from secfix.pipeline import Pipeline, apply_accepted  # noqa: E402
from secfix.validate import Validator  # noqa: E402

RULES = str(ROOT / "rules")
RESULTS = ROOT / "experiment" / "results"


def load_done(path):
    done = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                done.add((r["case"], r["config"], r["rep"]))
    return done


def final_check(validator, source, groups, path_suffix=".py"):
    """Aplica todos los parches aceptados y mide si el caso quedó reparado."""
    patched = apply_accepted(source, groups)
    with tempfile.TemporaryDirectory() as tmp:
        p = pathlib.Path(tmp, "final" + path_suffix)
        p.write_text(patched, encoding="utf-8")
        return validator.run_harness(str(p))


def run_one(case, config, rep, llm):
    rel = f"experiment/cases/{case['id']}.py"
    full_spec = {"functional": case["functional"], "exploit": case["exploit"]}
    val_spec = full_spec if config != "C1b" else {"functional": case["functional"]}
    validator = Validator(RULES, str(ROOT), harness_spec=val_spec)
    mode = "sast-only" if config == "C0" else "full"
    calls0 = (llm.calls, llm.prompt_tokens, llm.completion_tokens) if llm else (0, 0, 0)
    pipe = Pipeline(RULES, str(ROOT), llm=llm, validator=validator, mode=mode,
                    log=lambda m: print("   " + m, file=sys.stderr))
    t0 = time.monotonic()
    res = pipe.run({rel: None})
    findings, groups = res["findings"], res["groups"]

    if config == "C0":
        predicted = len(findings) > 0
    else:
        predicted = any(f.verdict == "TP" for f in findings)

    fixed, final = False, None
    if config != "C0" and groups and all(g.accepted for g in groups):
        final_validator = Validator(RULES, str(ROOT), harness_spec=full_spec)
        final = final_check(final_validator, res["sources"][rel], groups)
        fixed = bool(final.get("functional")) and final.get("exploitable") is False

    row = {
        "case": case["id"], "cwe": case["cwe"], "label": case["vulnerable"],
        "config": config, "rep": rep, "model": llm.model if llm else None,
        "predicted": predicted,
        "n_findings": len(findings),
        "n_tp": sum(f.verdict == "TP" for f in findings),
        "n_fp": sum(f.verdict == "FP" for f in findings),
        "n_groups": len(groups),
        "n_accepted": sum(g.accepted for g in groups),
        "attempts": sum(g.attempts for g in groups),
        "patch_broke_function": any(h["details"] and any("V3 funcional=FALLA" in d for d in h["details"])
                                    for g in groups for h in g.history),
        "fixed": fixed,
        "final_check": final,
        "seconds": round(time.monotonic() - t0, 2),
        "llm_calls": (llm.calls - calls0[0]) if llm else 0,
        "prompt_tokens": (llm.prompt_tokens - calls0[1]) if llm else 0,
        "completion_tokens": (llm.completion_tokens - calls0[2]) if llm else 0,
        "verdicts": [{"rule": f.short_rule, "line": f.line, "verdict": f.verdict,
                      "confidence": f.confidence, "justification": f.justification} for f in findings],
    }
    patches = [g.to_dict() for g in groups]
    return row, patches


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--configs", default="C0,C1")
    ap.add_argument("--reps", type=int, default=1)
    ap.add_argument("--rep-offset", type=int, default=0, help="Para repartir repeticiones entre cuentas")
    ap.add_argument("--cases", default="", help="Filtro por prefijo, p. ej. 's0,x0'")
    ap.add_argument("--model", default=None)
    ap.add_argument("--out", default=str(RESULTS / "runs.jsonl"))
    a = ap.parse_args()

    cases = yaml.safe_load((ROOT / "experiment" / "cases.yaml").read_text(encoding="utf-8"))["cases"]
    if a.cases:
        prefixes = tuple(p.strip() for p in a.cases.split(","))
        cases = [c for c in cases if c["id"].startswith(prefixes)]
    configs = [c.strip() for c in a.configs.split(",")]
    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    (RESULTS / "patches").mkdir(parents=True, exist_ok=True)
    done = load_done(out)
    llm = LLMClient(model=a.model) if any(c != "C0" for c in configs) else None

    for rep in range(a.rep_offset, a.rep_offset + a.reps):
        for config in configs:
            for case in cases:
                key = (case["id"], config, rep)
                if key in done:
                    continue
                print(f"[rep {rep}] {config} {case['id']}", file=sys.stderr)
                try:
                    row, patches = run_one(case, config, rep, llm if config != "C0" else None)
                except LLMError as e:
                    print(f"\nDetenido por el LLM: {e}\nVuelve a ejecutar el mismo comando más tarde; "
                          "los casos completados no se repiten.", file=sys.stderr)
                    return 2
                with out.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                (RESULTS / "patches" / f"{config}_r{rep}_{case['id']}.json").write_text(
                    json.dumps(patches, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    if llm:
        print(f"Uso del LLM: {llm.usage()}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
