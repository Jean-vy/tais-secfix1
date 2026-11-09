"""CLI de secfix.

  python -m secfix.cli pr     # dentro de GitHub Actions, en un evento pull_request
  python -m secfix.cli scan lab/routes/demo.py            # local, archivo completo
  python -m secfix.cli scan --base main --head HEAD       # local, solo el diff
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from secfix.diff import git_diff, parse_diff
from secfix.llm import LLMClient
from secfix.pipeline import Pipeline
from secfix.report import GitHubReporter, metrics, summary_markdown, write_json
from secfix.validate import Validator


def common_args(p):
    p.add_argument("--rules", default=os.environ.get("SECFIX_RULES", "rules/"))
    p.add_argument("--mode", choices=["full", "sast-only"], default="full")
    p.add_argument("--model", default=None, help="Modelo del LLM (por defecto SECFIX_MODEL o openai/gpt-oss-120b)")
    p.add_argument("--test-cmd", default=None, help="Comando de pruebas para V3 (p. ej. 'pytest -q lab/tests')")
    p.add_argument("--exploit-cmd", default=None, help="Comando de pruebas de explotación para V4")
    p.add_argument("--metrics-out", default="secfix-out/metrics.json")
    p.add_argument("--max-attempts", type=int, default=2)


def build_pipeline(a, repo_root="."):
    llm = LLMClient(model=a.model) if a.mode == "full" else None
    validator = Validator(a.rules, repo_root, test_cmd=a.test_cmd, exploit_cmd=a.exploit_cmd)
    return Pipeline(a.rules, repo_root, llm=llm, validator=validator, mode=a.mode,
                    max_attempts=a.max_attempts, log=lambda m: print(m, file=sys.stderr)), llm


def cmd_pr(a) -> int:
    event = json.load(open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8"))
    pr = event["pull_request"]
    base, head = pr["base"]["sha"], pr["head"]["sha"]
    diff = parse_diff(git_diff(base, head))
    targets = {p: v["added"] for p, v in diff.items()}
    pipe, llm = build_pipeline(a)
    result = pipe.run(targets)
    md = summary_markdown(result, a.mode)

    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(md + "\n")
    if not a.no_comment:
        rep = GitHubReporter(os.environ["GITHUB_REPOSITORY"], pr["number"], os.environ["GITHUB_TOKEN"], head)
        rep.post_review([g for g in result["groups"]], {p: v["commentable"] for p, v in diff.items()})
        rep.upsert_summary(md)
    write_json(a.metrics_out, metrics(result, {"pr": pr["number"], "head": head, "mode": a.mode,
                                               "llm": llm.usage() if llm else None}))
    print(md)
    blocking = [f for f in result["findings"] if a.mode == "sast-only" or f.verdict == "TP"]
    return 1 if (blocking and a.fail_on_findings) else 0


def cmd_scan(a) -> int:
    if a.base:
        diff = parse_diff(git_diff(a.base, a.head))
        targets = {p: v["added"] for p, v in diff.items()}
    else:
        targets = {p: None for p in a.paths}
    pipe, llm = build_pipeline(a)
    result = pipe.run(targets)
    md = summary_markdown(result, a.mode)
    for g in result["groups"]:
        md += f"\n\n### Parche {g.group_id} ({g.path}:{g.start}-{g.end}) — {'VALIDADO' if g.accepted else 'rechazado'}\n"
        md += "\n".join(f"- {d}" for d in (g.validation.details if g.validation else []))
        if g.fixed_code:
            md += f"\n\n```python\n{g.fixed_code}\n```"
    write_json(a.metrics_out, metrics(result, {"mode": a.mode, "llm": llm.usage() if llm else None}))
    print(md)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="secfix")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pr", help="Analiza el pull request actual (GitHub Actions)")
    common_args(p)
    p.add_argument("--no-comment", action="store_true")
    p.add_argument("--no-fail", dest="fail_on_findings", action="store_false")
    s = sub.add_parser("scan", help="Analiza archivos o un diff en local")
    common_args(s)
    s.add_argument("paths", nargs="*")
    s.add_argument("--base")
    s.add_argument("--head", default="HEAD")
    a = ap.parse_args(argv)
    return cmd_pr(a) if a.cmd == "pr" else cmd_scan(a)


if __name__ == "__main__":
    sys.exit(main())
