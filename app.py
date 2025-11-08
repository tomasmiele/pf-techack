# app.py — Phishing Detector (MVP) — heurística avançada + histórico/export
# Regra ajustada: erro em blacklist não rebaixa sozinho para suspicious
# Run: python -m uvicorn app:app --reload

import os
import re
import json
import socket
import ssl
import asyncio
from datetime import datetime, timezone
from typing import Optional
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
# Config/constantes
# -----------------------------

SUSPICIOUS_CHARS = set("@%;<>'\"\\|{}[]^~`")
LEET_PATTERN = re.compile(r"[0-9@$!]+")
IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

OPENPHISH_FEED = "https://openphish.com/feed.txt"
URLHAUS_URL_LOOKUP = "https://urlhaus.abuse.ch/api/v1/url/"

DYNAMIC_DNS_SUFFIXES = {
    "no-ip.com", "hopto.org", "zapto.org", "servehttp.com", "dyndns.org",
    "dyndns.com", "duckdns.org", "myftp.biz", "ddns.net", "ath.cx",
    "freeddns.org"
}

KNOWN_BRANDS = {
    "google.com", "paypal.com", "microsoft.com", "facebook.com",
    "apple.com", "amazon.com", "bankofamerica.com", "itau.com.br",
    "nubank.com.br", "bradesco.com.br", "santander.com.br"
}

HISTORY_LIMIT = 200
HISTORY = []

# -----------------------------
# Utils
# -----------------------------

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

# -----------------------------
# Heurísticas básicas
# -----------------------------

def heuristic_checks(url: str):
    parsed, domain, sub = domain_parts(url)
    findings = []
    host = parsed.hostname or ""

    if IP_PATTERN.match(host):
        findings.append(("ip_in_url", f"Host é um IP ({host})."))

    if host.startswith("xn--") or ".xn--" in host:
        findings.append(("punycode_idn", "Uso de Punycode (IDN) no domínio."))

    if sub:
        sub_count = len(sub.split("."))
        if sub_count >= 3:
            findings.append(("excessive_subdomains", f"Subdomínios excessivos ({sub_count})."))

    bare = domain.split(".")[0] if domain else ""
    if LEET_PATTERN.search(bare):
        findings.append(("leet_in_domain", f"Possível substituição por números/caracteres no domínio ('{bare}')."))

    if any(ch in SUSPICIOUS_CHARS for ch in url):
        findings.append(("suspicious_chars", "Caracteres especiais suspeitos na URL."))

    if len(url) > 120:
        findings.append(("long_url", f"URL muito longa ({len(url)} chars)."))

    return findings

# -----------------------------
# Blacklists (OpenPhish + URLhaus)
# -----------------------------

OPENPHISH_FEED = os.getenv("OPENPHISH_FEED", "https://openphish.com/feed.txt")
OPENPHISH_CACHE = os.getenv("OPENPHISH_CACHE", "openphish_cache.txt")

async def check_openphish(url: str) -> dict:
    """
    Checa o feed público do OpenPhish.
    - Se o feed estiver disponível: faz a verificação normal e retorna {"source":"OpenPhish","listed":bool}
    - Se o feed NÃO estiver disponível por rede/timeout, tenta usar um cache local (se existir)
      e retorna {"source":"OpenPhish","listed":False,"note":"feed_unavailable"}. Não retorna 'error'.
    """
    u_host = urlparse(url).netloc
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            # requisita o feed com header simples para evitar bloqueios
            r = await client.get(OPENPHISH_FEED, headers={"User-Agent": "phish-detector/1.0"})
            r.raise_for_status()
            feed = r.text.splitlines()
        hit = any(
            (url in line)
            or (
                (lambda p: p.scheme and p.netloc)(urlparse(line))
                and urlparse(line).netloc == u_host
            )
            for line in feed
        )
        # atualizar cache (silenciosamente; falhas em cache não quebram)
        try:
            with open(OPENPHISH_CACHE, "w", encoding="utf-8") as f:
                f.write("\n".join(feed))
        except Exception:
            pass
        return {"source": "OpenPhish", "listed": bool(hit)}
    except Exception:
        # tentativa de fallback: usar cache local se existir
        try:
            with open(OPENPHISH_CACHE, "r", encoding="utf-8") as f:
                feed = f.read().splitlines()
            hit = any((url in line) or (urlparse(line).netloc == u_host) for line in feed)
            return {"source": "OpenPhish", "listed": bool(hit), "note": "cached_used"}
        except Exception:
            # quando nem o cache existe, retornamos apenas uma nota - sem 'error'
            return {"source": "OpenPhish", "listed": False, "note": "feed_unavailable"}

async def check_urlhaus(url: str) -> dict:
    try:
        if not re.match(r"^https?://", url, flags=re.I):
            return {"source": "URLhaus", "listed": False, "note": "invalid url format (missing scheme)"}

        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(URLHAUS_URL_LOOKUP, data={"url": url})
            text = r.text
            r.raise_for_status()
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as je:
            return {"source": "URLhaus", "listed": False, "error": f"JSONDecodeError: {je}", "raw": text[:300]}

        status = (payload.get("query_status") or "").lower()
        if status in {"no_results", "no results"}:
            return {"source": "URLhaus", "listed": False, "note": "no results"}
        if "invalid" in status:
            return {"source": "URLhaus", "listed": False, "note": status}
        if status == "ok":
            url_status = payload.get("url_status")
            threat = payload.get("threat")
            listed = url_status in {"online", "offline"}
            note = f"status={url_status}" + (f"; threat={threat}" if threat else "")
            return {"source": "URLhaus", "listed": bool(listed), "note": note}

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
# Heurística avançada
# -----------------------------

def _whois_basic_sync(domain: str) -> dict:
    info = {"domain": domain}
    try:
        import whois  # type: ignore
    except Exception:
        info["note"] = "pacote 'whois' não instalado"
        return info

    try:
        w = whois.whois(domain)
        created = getattr(w, "creation_date", None)
        if isinstance(created, list):
            created = min([d for d in created if hasattr(d, "year")], default=None)
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            info["creation_date"] = created.isoformat()
            age_days = int((datetime.now(timezone.utc) - created).total_seconds() // 86400)
            info["age_days"] = age_days
        info["registrar"] = getattr(w, "registrar", None)
    except Exception as e:
        info["error"] = repr(e)
    return info

async def whois_age(domain: str) -> dict:
    return await asyncio.to_thread(_whois_basic_sync, domain)

def is_dynamic_dns(domain: str) -> Optional[str]:
    for suffix in DYNAMIC_DNS_SUFFIXES:
        if domain.endswith(suffix):
            return suffix
    return None

def _parse_notafter(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None

def _ssl_fetch_sync(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    ctx = ssl.create_default_context()
    report = {"host": host, "port": port, "valid": False}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                report["cert"] = cert
                report["valid"] = True
                not_after = _parse_notafter(cert.get("notAfter"))
                if not_after:
                    report["not_after"] = not_after.isoformat()
                    report["days_left"] = int((not_after - datetime.now(timezone.utc)).total_seconds() // 86400)

                def _read_name(seq):
                    try:
                        return dict(x for y in seq for x in y)
                    except Exception:
                        return {}
                report["issuer"] = _read_name(cert.get("issuer", []))
                report["subject"] = _read_name(cert.get("subject", []))
                san = cert.get("subjectAltName") or []
                report["sans"] = [v for (k, v) in san if k.lower() == "dns"]
    except ssl.SSLCertVerificationError as e:
        report["error"] = f"SSLCertVerificationError: {e}"
    except Exception as e:
        report["error"] = repr(e)
    return report

async def ssl_info(host: str) -> dict:
    return await asyncio.to_thread(_ssl_fetch_sync, host)

async def detect_redirects(url: str) -> dict:
    out = {"chain": [], "suspicious": False}
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
            r = await client.get(url)
            chain = [str(h.headers.get("Location") or h.url) for h in r.history] + [str(r.url)]
            out["chain"] = chain

            def base(eurl: str) -> str:
                ext = tldextract.extract(urlparse(eurl).netloc)
                return ".".join(p for p in [ext.domain, ext.suffix] if p)

            if len(chain) - 1 > 3:
                out["suspicious"] = True
                out["reason"] = "redirects>3"
            else:
                bases = [base(u) for u in chain if "://" in u]
                if len(set(bases)) > 1:
                    out["suspicious"] = True
                    out["reason"] = "cross-domain redirect"
    except Exception as e:
        out["error"] = repr(e)
    return out

def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            ins = cur[j-1] + 1
            dele = prev[j] + 1
            subst = prev[j-1] + (ca != cb)
            cur.append(min(ins, dele, subst))
        prev = cur
    return prev[-1]

def brand_similarity(domain: str):
    ext = tldextract.extract(domain)
    sld = (ext.domain or "").lower()
    tld = (ext.suffix or "").lower()
    base = ".".join(p for p in [sld, tld] if p)

    if not sld or not tld:
        return {"base": base or domain, "closest": None, "lookalike": False}

    if sld in {"example", "localhost", "test"}:
        return {"base": base, "closest": None, "lookalike": False}

    best = None
    best_dist = 1_000

    for brand in KNOWN_BRANDS:
        bext = tldextract.extract(brand)
        bsld = (bext.domain or "").lower()
        btld = (bext.suffix or "").lower()
        if not bsld or not btld:
            continue
        if btld != tld:
            continue
        if abs(len(sld) - len(bsld)) > 2:
            continue
        dist = levenshtein(sld, bsld)
        if dist < best_dist:
            best_dist = dist
            best = {"brand": brand, "distance": dist}

    flag = bool(best and best["distance"] <= 1 and sld != tldextract.extract(best["brand"]).domain.lower())
    return {"base": base, "closest": best, "lookalike": flag}

async def content_probe(url: str) -> dict:
    out = {"login_form": False, "password_field": False, "sensitive_keywords": []}
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            r = await client.get(url)
            r.raise_for_status()
            html = r.text.lower()
        if re.search(r"<form[^>]+(login|signin|auth)", html):
            out["login_form"] = True
        if re.search(r"type\s*=\s*\"password\"", html):
            out["password_field"] = True
        keywords = ["cpf", "cartão", "cartao", "credit card", "ssn", "otp", "one-time password", "cvv"]
        out["sensitive_keywords"] = [k for k in keywords if k in html]
    except Exception as e:
        out["error"] = repr(e)
    return out

# -----------------------------
# Veredito + alerts (ajuste principal aqui)
# -----------------------------

def verdict(heuristics: list, blacklists: list, advanced: dict) -> dict:
    # 1) Listado em qualquer feed => malicious
    if any(b.get("listed") for b in blacklists):
        return {"label": "malicious", "score": None, "color": "#e11d48"}

    # 2) 'invalid' explícito em qualquer feed => suspicious
    def is_invalid(b: dict) -> bool:
        return "invalid" in (b.get("note") or "").lower()

    if any(is_invalid(b) for b in blacklists):
        return {"label": "suspicious", "score": None, "color": "#f59e0b"}

    # 3) Score por heurística/avançado (erros de rede não contam sozinhos)
    weight = {
        "ip_in_url": 3,
        "punycode_idn": 2,
        "excessive_subdomains": 2,
        "leet_in_domain": 3,
        "suspicious_chars": 1,
        "long_url": 1,
        "ssl_invalid": 3,
        "domain_young": 2,
        "dynamic_dns": 3,
        "redirects_suspicious": 2,
        "lookalike_brand": 3,
        "content_suspicious": 2,
    }
    score = sum(weight.get(k, 1) for k, _ in heuristics)

    sslr = advanced.get("ssl", {})
    if sslr and (not sslr.get("valid")):
        score += weight["ssl_invalid"]

    who = advanced.get("whois", {})
    if who and (who.get("age_days") is not None) and who["age_days"] < 30:
        score += weight["domain_young"]

    if advanced.get("dynamic_dns", {}).get("matched"):
        score += weight["dynamic_dns"]

    red = advanced.get("redirects", {})
    if red.get("suspicious"):
        score += weight["redirects_suspicious"]

    sim = advanced.get("similarity", {})
    if sim.get("lookalike"):
        score += weight["lookalike_brand"]

    cont = advanced.get("content", {})
    if cont and (cont.get("login_form") or cont.get("password_field") or cont.get("sensitive_keywords")):
        score += weight["content_suspicious"]

    if score >= 3:
        return {"label": "suspicious", "score": score, "color": "#f59e0b"}
    else:
        return {"label": "safe", "score": score, "color": "#16a34a"}

def generate_alerts(heuristics: list, advanced: dict) -> list:
    alerts = []
    explanations = {
        "punycode_idn": (
            "Uso de Punycode (IDN): possibilidade de homograph attack",
            "Pode ser legítimo (caracteres não-ASCII). Verifique nome exibido e certificado."
        ),
        "excessive_subdomains": (
            "Subdomínios em excesso: pode esconder o domínio real",
            "Serviços legítimos (CDNs/multi-tenant) também usam subdomínios longos."
        ),
    }
    weights = {"punycode_idn": 2, "excessive_subdomains": 2}
    for k, _ in heuristics:
        if weights.get(k) == 2 and k in explanations:
            title, why = explanations[k]
            alerts.append({"key": k, "title": title, "why_not_certain": why})

    sslr = advanced.get("ssl", {})
    if sslr and (not sslr.get("valid")):
        alerts.append({"key": "ssl_invalid", "title": "Problema no certificado SSL", "why_not_certain": sslr.get("error", "Certificado inválido/indisponível.")})

    who = advanced.get("whois", {})
    if who and (who.get("age_days") is not None) and who["age_days"] < 30:
        alerts.append({"key": "domain_young", "title": "Domínio muito novo (<30 dias)", "why_not_certain": "Domínios legítimos novos existem; combine com outros sinais."})

    dyn = advanced.get("dynamic_dns", {})
    if dyn.get("matched"):
        alerts.append({"key": "dynamic_dns", "title": f"DNS dinâmico detectado ({dyn.get('suffix')})", "why_not_certain": "DNS dinâmico pode ser legítimo em testes/labs, mas é comum em campanhas de phishing."})

    red = advanced.get("redirects", {})
    if red.get("suspicious"):
        alerts.append({"key": "redirects_suspicious", "title": "Redirecionamentos suspeitos", "why_not_certain": red.get("reason", "Muitos hops ou troca de domínio.")})

    sim = advanced.get("similarity", {})
    if sim.get("lookalike"):
        alerts.append({"key": "lookalike_brand", "title": "Parecido com marca conhecida", "why_not_certain": f"Domínio base próximo de {sim.get('closest',{}).get('brand')} (distância de edição pequena), pode ser falsificação."})

    cont = advanced.get("content", {})
    if cont and (cont.get("login_form") or cont.get("password_field") or cont.get("sensitive_keywords")):
        reason = []
        if cont.get("login_form"): reason.append("formulário de login")
        if cont.get("password_field"): reason.append("campo de senha")
        if cont.get("sensitive_keywords"): reason.append("palavras sensíveis: " + ", ".join(cont["sensitive_keywords"]))
        alerts.append({"key": "content_suspicious", "title": "Conteúdo solicita credenciais/dados", "why_not_certain": "; ".join(reason)})

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
    parsed, domain, _ = domain_parts(norm)
    host = parsed.hostname or domain

    heur = heuristic_checks(norm)
    bl = await blacklist_checks(norm)

    who_task = asyncio.create_task(whois_age(domain))
    ssl_task = asyncio.create_task(ssl_info(host))
    red_task = asyncio.create_task(detect_redirects(norm))
    cont_task = asyncio.create_task(content_probe(norm))
    who, sslr, red, cont = await asyncio.gather(who_task, ssl_task, red_task, cont_task)

    dyn_suffix = is_dynamic_dns(domain)
    similarity = brand_similarity(domain)

    advanced = {
        "whois": who,
        "ssl": sslr,
        "redirects": red,
        "dynamic_dns": {"matched": bool(dyn_suffix), "suffix": dyn_suffix},
        "similarity": similarity,
        "content": cont,
    }

    v = verdict(heur, bl, advanced)
    alerts = generate_alerts(heur, advanced)

    result = {
        "input": url,
        "normalized": norm,
        "heuristics": [{"key": k, "detail": d} for k, d in heur],
        "blacklists": bl,
        "advanced": advanced,
        "verdict": v,
        "alerts": alerts,
    }

    HISTORY.append({"ts": datetime.now(timezone.utc).isoformat(), **result})
    if len(HISTORY) > HISTORY_LIMIT:
        del HISTORY[: len(HISTORY) - HISTORY_LIMIT]

    return JSONResponse(result)

@app.get("/history")
async def history():
    return JSONResponse({"items": HISTORY[-HISTORY_LIMIT:]})

@app.get("/export")
async def export_history():
    return JSONResponse({"exported_at": datetime.now(timezone.utc).isoformat(), "items": HISTORY[-HISTORY_LIMIT:]})
