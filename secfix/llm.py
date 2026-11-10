"""Cliente LLM compatible con la API de chat de OpenAI.

GitHub Models se retiró el 30/07/2026; por defecto se usa Groq (plan gratuito).
Configuración por variables de entorno:
  SECFIX_LLM_TOKEN     API key del proveedor (obligatoria)
  SECFIX_LLM_ENDPOINT  URL de /chat/completions (por defecto, Groq)
  SECFIX_MODEL         modelo (por defecto, openai/gpt-oss-120b)
Sirve cualquier proveedor compatible con OpenAI (Gemini, OpenRouter, OpenAI...).
"""
from __future__ import annotations

import json
import os
import re
import time

import requests

DEFAULT_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-oss-120b"


class LLMError(RuntimeError):
    pass


class LLMClient:
    def __init__(self, model: str | None = None, token: str | None = None,
                 endpoint: str | None = None, min_interval: float | None = None,
                 max_retries: int = 6, timeout: int = 120):
        # `or` en vez del default de .get(): en Actions una variable sin definir llega como "".
        self.model = model or os.environ.get("SECFIX_MODEL") or DEFAULT_MODEL
        self.token = token or os.environ.get("SECFIX_LLM_TOKEN")
        self.endpoint = endpoint or os.environ.get("SECFIX_LLM_ENDPOINT") or DEFAULT_ENDPOINT
        # Margen para los planes gratuitos (~15 solicitudes/minuto).
        self.min_interval = float(min_interval if min_interval is not None
                                  else os.environ.get("SECFIX_MIN_INTERVAL", 4.5))
        self.max_retries = max_retries
        self.timeout = timeout
        self._last = 0.0
        self.calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0

    def _wait_turn(self):
        delta = time.monotonic() - self._last
        if delta < self.min_interval:
            time.sleep(self.min_interval - delta)
        self._last = time.monotonic()

    def chat_json(self, system: str, user: str) -> dict:
        if not self.token:
            raise LLMError("Falta la API key del LLM: define SECFIX_LLM_TOKEN "
                           "(en GitHub, el secret LLM_API_KEY del repositorio).")
        body = {
            "model": self.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json",
                   "Accept": "application/json"}
        delay = 10.0
        for attempt in range(self.max_retries):
            self._wait_turn()
            try:
                r = requests.post(self.endpoint, headers=headers, json=body, timeout=self.timeout)
            except requests.RequestException as e:
                last_err = f"error de red: {e}"
            else:
                if r.status_code == 200:
                    try:
                        data = r.json()
                        content = data["choices"][0]["message"]["content"]
                    except (ValueError, KeyError, IndexError, TypeError):
                        # Un 200 que no es respuesta de chat indica un endpoint equivocado o
                        # retirado (GitHub Models responde "OK"): reintentar no sirve.
                        raise LLMError(
                            f"{self.endpoint} respondió 200 pero no con una respuesta de chat "
                            f"(content-type={r.headers.get('content-type')!r}): {r.text[:300]!r}. "
                            "Revisa SECFIX_LLM_ENDPOINT.")
                    self.calls += 1
                    usage = data.get("usage") or {}
                    self.prompt_tokens += usage.get("prompt_tokens", 0)
                    self.completion_tokens += usage.get("completion_tokens", 0)
                    return parse_json(content)
                last_err = f"HTTP {r.status_code}: {r.text[:300]}"
                print(f"  [secfix] LLM: {last_err}", flush=True)
                if r.status_code not in (429, 500, 502, 503, 504):
                    raise LLMError(last_err)
                retry_after = r.headers.get("retry-after")
                if retry_after and retry_after.isdigit():
                    wait = int(retry_after)
                    if wait > 600:  # cuota diaria agotada: no tiene sentido esperar
                        raise LLMError(f"Cuota agotada (retry-after={wait}s). {last_err}")
                    delay = max(delay, wait)
            time.sleep(delay)
            delay = min(delay * 2, 120)
        raise LLMError(f"El LLM no respondió tras {self.max_retries} intentos: {last_err}")

    def usage(self) -> dict:
        return {"model": self.model, "calls": self.calls, "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens}


def parse_json(text: str) -> dict:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            raise LLMError(f"Respuesta no es JSON: {text[:200]}")
        return json.loads(m.group(0))
