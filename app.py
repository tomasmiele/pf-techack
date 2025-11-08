# app.py — Phishing Detector (MVP) — backend separado com debug e regra: erro/invalid em blacklist => suspicious
# Run: python -m uvicorn app:app --reload
# Requires: pip install -r requirements.txt

import os
import re
import json
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import httpx
import tldextract

app = FastAPI(title="Phishing Detector — MVP")

# Frontend (pasta estática)
app.mount("/static", StaticFiles(directory="static"), name="static")

# -----------------------------
# Utilitários e heurísticas
# -----------------------------

SUSPICIOUS_CHARS = set("@%;<>'\"\\|{}[]^~`")
LEET_PATTERN = re.compile(r"[0-9@$!]+")
IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z]+://", url):
        url = "http://" + url
    return url


def domain_parts(url: str):
    parsed = urlparse(url)
    ext = tldextract.extract(parsed.netloc)
    domain = ".".join(p for p in [ext.domain, ext.suffix] if p)
    subdomain = ext.subdomain
    return parsed, domain, subdomain


def heuristic_checks(url: str):
    parsed, domain, sub = domain_parts(url)
    findings = []

    host = parsed.hostname or ""

    # 1) IP em vez de domínio
    if IP_PATTERN.match(host):
        findings.append(("ip_in_url", f"Host é um IP ({host})."))

    # 2) Punycode (IDN)
    if host.startswith("xn--") or ".xn--" in host:
        findings.append(("punycode_idn", "Uso de Punycode (IDN) no domínio."))

    # 3) Subdomínios em excesso
    if sub:
        sub_count = len(sub.split("."))
        if sub_count >= 3:
            findings.append(("excessive_subdomains", f"Subdomínios excessivos ({sub_count})."))

    # 4) Leet / substituição por números
    bare = domain.split(".")[0] if domain else ""
    if LEET_PATTERN.search(bare):
        findings.append(("leet_in_domain", f"Possível substituição por números/caracteres no domínio ('{bare}')."))

    # 5) Caracteres especiais suspeitos
    if any(ch in SUSPICIOUS_CHARS for ch in url):
        findings.append(("suspicious_chars", "Caracteres especiais suspeitos na URL."))

    # 6) URL muito longa
    if len(url) > 120:
        findings.append(("long_url", f"URL muito longa ({len(url)} chars)."))

    return findings


# -----------------------------
# Blacklists (OpenPhish + URLhaus)
# -----------------------------

OPENPHISH_FEED = "https://openphish.com/feed.txt"
URLHAUS_URL_LOOKUP = "https://urlhaus.abuse.ch/api/v1/url/"


async def check_openphish(url: str) -> dict:
    """Checa o feed público do OpenPhish (best-effort)."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(OPENPHISH_FEED)
            r.raise_for_status()
            feed = r.text.splitlines()
        u_host = urlparse(url).netloc
        hit = any(
            (url in line)
            or (
                (lambda p: p.scheme and p.netloc)(urlparse(line))
                and urlparse(line).netloc == u_host
            )
            for line in feed
        )
        return {"source": "OpenPhish", "listed": bool(hit)}
    except Exception as e:
        return {"source": "OpenPhish", "listed": False, "error": repr(e)}


async def check_urlhaus(url: str) -> dict:
    """Consulta URLhaus (abuse.ch) via API pública (POST). Retorna erros detalhados."""
    try:
        # URLhaus exige http(s) no valor de 'url'
        if not re.match(r"^https?://", url, flags=re.I):
            return {"source": "URLhaus", "listed": False, "note": "invalid url format (missing scheme)"}

        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(URLHAUS_URL_LOOKUP, data={"url": url})
            text = r.text  # para debug em caso de JSON inválido
            r.raise_for_status()
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as je:
            return {"source": "URLhaus", "listed": False, "error": f"JSONDecodeError: {je}", "raw": text[:300]}

        status = payload.get("query_status")

        # Casos não-erro, mas também não listados:
        if status in {"no_results", "no results"}:
            return {"source": "URLhaus", "listed": False, "note": "no results"}

        if status == "invalid url format":
            return {"source": "URLhaus", "listed": False, "note": "invalid url format"}

        # Caso OK (achou algo)
        if status == "ok":
            url_status = payload.get("url_status")
            threat = payload.get("threat")
            listed = url_status in {"online", "offline"}  # conhecido pelo URLhaus
            note = f"status={url_status}" + (f"; threat={threat}" if threat else "")
            return {"source": "URLhaus", "listed": bool(listed), "note": note}

        # Qualquer outro status inesperado: retornar como 'error' para debug
        return {"source": "URLhaus", "listed": False, "error": f"Unexpected query_status: {status}", "raw": str(payload)[:300]}

    except httpx.ConnectError as ce:
        return {"source": "URLhaus", "listed": False, "error": f"ConnectError: {repr(ce)}"}
    except httpx.ReadTimeout as te:
        return {"source": "URLhaus", "listed": False, "error": f"ReadTimeout: {repr(te)}"}
    except Exception as e:
        return {"source": "URLhaus", "listed": False, "error": repr(e)}


async def blacklist_checks(url: str):
    url = normalize_url(url)
    res_openphish = await check_openphish(url)
    res_urlhaus = await check_urlhaus(url)
    return [res_openphish, res_urlhaus]


# -----------------------------
# Veredito + alerts (leet = alto)
# -----------------------------

def verdict(heuristics: list, blacklists: list) -> dict:
    """
    Regras:
      1) Se qualquer blacklist listou => malicious
      2) Se qualquer blacklist teve ERRO ou 'invalid ...' => suspicious
      3) Caso contrário, soma ponderada de heurísticas (>=3 => suspicious; senão safe)
    """
    # 1) Blacklist => malicious
    if any(b.get("listed") for b in blacklists):
        return {"label": "malicious", "score": None, "color": "#e11d48"}

    # 2) Erros/Invalid em qualquer feed => suspicious
    def is_invalid_or_error(b: dict) -> bool:
        note = (b.get("note") or "").lower()
        err = b.get("error")
        return bool(err) or ("invalid" in note)

    if any(is_invalid_or_error(b) for b in blacklists):
        return {"label": "suspicious", "score": None, "color": "#f59e0b"}

    # 3) Heurísticas (pesos)
    weight = {
        "ip_in_url": 3,
        "punycode_idn": 2,          # médio -> alerta
        "excessive_subdomains": 2,  # médio -> alerta
        "leet_in_domain": 3,        # alto
        "suspicious_chars": 1,
        "long_url": 1,
    }
    score = sum(weight.get(k, 1) for k, _ in heuristics)

    if score >= 3:
        return {"label": "suspicious", "score": score, "color": "#f59e0b"}
    else:
        return {"label": "safe", "score": score, "color": "#16a34a"}


def generate_alerts(heuristics: list) -> list:
    weight = {
        "ip_in_url": 3,
        "punycode_idn": 2,
        "excessive_subdomains": 2,
        "leet_in_domain": 3,
        "suspicious_chars": 1,
        "long_url": 1,
    }
    explanations = {
        "punycode_idn": (
            "Uso de Punycode (IDN): possibilidade de homograph attack",
            "Nem todo domínio em Punycode é malicioso — pode ser legítimo (caracteres não-ASCII). Verifique o domínio renderizado e o certificado SSL."
        ),
        "excessive_subdomains": (
            "Subdomínios em excesso: pode esconder o domínio real",
            "Alguns serviços legítimos usam subdomínios longos (CDNs, multi-tenant). Combine com outros sinais antes de concluir."
        ),
    }
    keys = {k for k, _ in heuristics}
    alerts = []
    for key in keys:
        if weight.get(key) == 2 and key in explanations:
            title, why = explanations[key]
            alerts.append({"key": key, "title": title, "why_not_certain": why})
    return alerts


# -----------------------------
# Endpoints
# -----------------------------

@app.get("/")
async def serve_frontend():
    return FileResponse("static/index.html")


@app.post("/analyze")
async def analyze(payload: dict):
    url = (payload.get("url") or "").strip()
    if not url:
        return JSONResponse({"error": "URL ausente."}, status_code=400)

    norm = normalize_url(url)
    heur = heuristic_checks(norm)
    bl = await blacklist_checks(norm)
    v = verdict(heur, bl)
    alerts = generate_alerts(heur)

    result = {
        "input": url,
        "normalized": norm,
        "heuristics": [{"key": k, "detail": d} for k, d in heur],
        "blacklists": bl,
        "verdict": v,
        "alerts": alerts,
    }
    return JSONResponse(result)
