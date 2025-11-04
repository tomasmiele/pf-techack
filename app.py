# app.py — Phishing Detector (MVP)
# Run: uvicorn app:app --reload
# Requires: pip install fastapi uvicorn httpx tldextract python-magic-bin==0.4.14 (Windows) or python-magic (Linux/Mac)
# (python-magic is not strictly required here; kept for future content checks.)

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import re
import os
import json
import httpx
import tldextract
from urllib.parse import urlparse

app = FastAPI(title="Phishing Detector — MVP")

# -----------------------------
# Utility: Heuristic checks
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

    # 1) IP address used instead of domain
    host = parsed.hostname or ""
    if IP_PATTERN.match(host):
        findings.append(("ip_in_url", f"Host é um IP ({host})."))

    # 2) Punycode (IDN) indicators
    if host.startswith("xn--") or ".xn--" in host:
        findings.append(("punycode_idn", "Uso de Punycode (IDN) no domínio."))

    # 3) Excessive subdomains
    if sub:
        sub_count = len(sub.split("."))
        if sub_count >= 3:
            findings.append(
                ("excessive_subdomains", f"Subdomínios excessivos ({sub_count}).")
            )

    # 4) Leet / números em substituição a letras no domínio
    #    e.g., g00gle, paypa1, micr0soft
    bare = domain.split(".")[0] if domain else ""
    if LEET_PATTERN.search(bare):
        findings.append(
            (
                "leet_in_domain",
                f"Possível substituição por números/caracteres no domínio (‘{bare}’).",
            )
        )

    # 5) Suspicious characters in full URL
    if any(ch in SUSPICIOUS_CHARS for ch in url):
        findings.append(("suspicious_chars", "Caracteres especiais suspeitos na URL."))

    # 6) Very long URL
    if len(url) > 120:
        findings.append(("long_url", f"URL muito longa ({len(url)} chars)."))

    return findings


# -----------------------------
# Blacklist lookups (best-effort)
# -----------------------------

OPENPHISH_FEED = "https://openphish.com/feed.txt"
URLHAUS_URL_LOOKUP = "https://urlhaus.abuse.ch/api/v1/url/"


async def check_openphish(url: str) -> dict:
    """Checks if the URL (or its domain) appears in OpenPhish feed (simple contains).
    Returns a dict with status and note. Errors are non-fatal.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(OPENPHISH_FEED)
            r.raise_for_status()
            feed = r.text.splitlines()
        hit = any(
            url in line
            or (
                urlparse(url).netloc
                in (
                    urlparse(line).netloc
                    if (lambda p: p.scheme and p.netloc)(urlparse(line))
                    else ""
                )
            )
            for line in feed
        )
        return {"source": "OpenPhish", "listed": bool(hit)}
    except Exception as e:
        return {"source": "OpenPhish", "listed": False, "error": str(e)}


async def check_urlhaus(url: str) -> dict:
    """Check Abuse.ch URLhaus (no API key)."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(URLHAUS_URL_LOOKUP, data={"url": url})
            r.raise_for_status()
            payload = r.json()
        status = payload.get("query_status")
        if status == "ok":
            url_status = payload.get("url_status")
            threat = payload.get("threat")
            listed = url_status in {"online", "offline"}  # known to URLhaus
            note = (
                f"status={url_status}; threat={threat}"
                if threat
                else f"status={url_status}"
            )
            return {"source": "URLhaus", "listed": bool(listed), "note": note}
        return {"source": "URLhaus", "listed": False, "note": status or "no match"}
    except Exception as e:
        return {"source": "URLhaus", "listed": False, "error": str(e)}


async def blacklist_checks(url: str):
    url = normalize_url(url)
    res_openphish = await check_openphish(url)
    res_urlhaus = await check_urlhaus(url)
    return [res_openphish, res_urlhaus]


# -----------------------------
# Verdict logic
# -----------------------------


def verdict(heuristics: list, blacklists: list) -> dict:
    flagged = any(b.get("listed") for b in blacklists)
    score = 0
    weight = {
        "ip_in_url": 3,
        "punycode_idn": 2,
        "excessive_subdomains": 2,
        "leet_in_domain": 2,
        "suspicious_chars": 1,
        "long_url": 1,
    }
    for k, _ in heuristics:
        score += weight.get(k, 1)

    # Simple policy: blacklist => malicious; else score >= 3 => suspicious; else safe
    if flagged:
        label = "malicious"
        color = "#e11d48"  # red-600
    elif score >= 3:
        label = "suspicious"
        color = "#f59e0b"  # amber-500
    else:
        label = "safe"
        color = "#16a34a"  # green-600

    return {"label": label, "score": score, "color": color}


# -----------------------------
# API
# -----------------------------


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(CONTENT_HTML)


@app.post("/analyze")
async def analyze(payload: dict):
    url = payload.get("url", "").strip()
    if not url:
        return JSONResponse({"error": "URL ausente."}, status_code=400)

    norm = normalize_url(url)
    heur = heuristic_checks(norm)
    bl = await blacklist_checks(norm)
    v = verdict(heur, bl)

    result = {
        "input": url,
        "normalized": norm,
        "heuristics": [{"key": k, "detail": d} for k, d in heur],
        "blacklists": bl,
        "verdict": v,
    }
    return JSONResponse(result)


# -----------------------------
# Inline HTML (no templates for MVP)
# -----------------------------

CONTENT_HTML = """
<!doctype html>
<html lang=\"pt-br\">
<head>
  <meta charset=\"utf-8\"/>
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>
  <title>Phishing Detector — MVP</title>
  <style>
    :root { --bg:#0b1020; --card:#121a2b; --muted:#8aa0b6; --ok:#16a34a; --warn:#f59e0b; --bad:#e11d48; }
    body{margin:0;font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu; background:var(--bg); color:white}
    .wrap{max-width:980px;margin:48px auto;padding:0 16px}
    .card{background:var(--card); border:1px solid rgba(255,255,255,.08); border-radius:16px; padding:20px; box-shadow:0 10px 30px rgba(0,0,0,.25)}
    .row{display:flex; gap:12px}
    input[type=url]{flex:1;padding:14px 16px;border-radius:12px;border:1px solid rgba(255,255,255,.12);background:#0d1424;color:white}
    button{padding:14px 18px;border-radius:12px;border:0;background:#2563eb;color:#fff;font-weight:600;cursor:pointer}
    table{width:100%;border-collapse:separate;border-spacing:0 8px;margin-top:16px}
    th,td{padding:10px 12px; text-align:left}
    th{color:var(--muted); font-weight:600}
    tr{background:#0e1729}
    .dot{display:inline-block;width:10px;height:10px;border-radius:999px;margin-right:8px;vertical-align:middle}
    .muted{color:var(--muted)}
    .pill{display:inline-flex;align-items:center;gap:8px;padding:6px 10px;border-radius:999px;font-size:12px;background:#0b1322;border:1px solid rgba(255,255,255,.08)}
    .mono{font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace}
  </style>
</head>
<body>
  <div class=\"wrap\">
    <h1>🔎 Phishing Detector — MVP</h1>
    <p class=\"muted\">Cole uma URL e veja indicadores básicos + listas de phishing (OpenPhish / PhishTank*).</p>

    <div class=\"card\">
      <div class=\"row\">
        <input id=\"url\" type=\"url\" placeholder=\"https://exemplo.com/login\"/>
        <button onclick=\"runCheck()\">Analisar</button>
      </div>
    </div>

    <div class=\"card\" style=\"margin-top:20px\">
      <table>
        <thead>
          <tr>
            <th>Status</th>
            <th>URL</th>
            <th>Heurísticas</th>
            <th>Listas</th>
          </tr>
        </thead>
        <tbody id=\"results\"></tbody>
      </table>
    </div>
  </div>

<script>
async function runCheck(){
  const url = document.getElementById('url').value.trim();
  if(!url){ alert('Informe uma URL.'); return; }
  const res = await fetch('/analyze', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({url})
  });
  if(!res.ok){ alert('Falha na análise.'); return; }
  const data = await res.json();
  addRow(data);
}

function esc(s){ return (s||'').toString().replace(/[&<>\"']/g, m=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[m])) }

function addRow(d){
  const verdict = d.verdict || {label:'safe', color:'#16a34a'};
  const heur = (d.heuristics||[]).map(h=>`<span class=\"pill\">${esc(h.key)}</span>`).join(' ');
  const bl = (d.blacklists||[]).map(b=>`<div class=\"pill\">${esc(b.source)}: <strong>${b.listed? 'LISTADO' : 'não'}</strong>${b.note? ' — '+esc(b.note): ''}</div>`).join(' ');
  const row = document.createElement('tr');
  row.innerHTML = `
    <td><span class=\"dot\" style=\"background:${verdict.color}\"></span>${esc(verdict.label)}</td>
    <td class=\"mono\">${esc(d.normalized||d.input)}</td>
    <td>${heur||'<span class=\"muted\">—</span>'}</td>
    <td>${bl||'<span class=\"muted\">—</span>'}</td>
  `;
  document.getElementById('results').prepend(row);
}
</script>
</body>
</html>
"""

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True
    )
