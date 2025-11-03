#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
parse_logs.py — Nota C (Opção 2)
Uso (único caso coberto):
    python src/parse_logs.py --url https://seu-servidor.com

- Concatena automaticamente '/access.log'
- Faz parsing do Combined Log Format
- Gera 1 atributo: suspicious_token_count (XSS/LFI/RFI)
- Salva CSV em data/processed/requests.csv
"""

import argparse
import csv
import datetime as dt
import os
import re
import sys
from typing import Dict, Iterable, Optional
from urllib.parse import urljoin, urlparse, unquote_plus

import requests

# Regex para Combined Log Format (Apache/Nginx)
CLF_RE = re.compile(
    r"^(?P<ip>\S+) "
    r"(?P<ident>\S+) "
    r"(?P<user>\S+) "
    r"\[(?P<time>[^\]]+)\] "
    r'"(?P<request>[^"]*)" '
    r"(?P<status>\d{3}) "
    r"(?P<size>\S+)"
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
    r"\s*$"
)

# Tokens simples de XSS + LFI/RFI (case-insensitive)
SUSPICIOUS_TOKENS = [
    # XSS
    "<script",
    "</script",
    "javascript:",
    "document.cookie",
    "onerror=",
    "onload=",
    # LFI/RFI
    "../",
    "..%2f",
    "%2e%2e%2f",
    "php://filter",
    "convert.base64",
    "include=",
    "etc/passwd",
    "?page=",
    "?p=",
]

OUT_PATH = "data/processed/requests.csv"
TIMEOUT_S = 30  # fixo, sem arg


def build_log_url(base_url: str) -> str:
    """Garante esquema e concatena '/access.log' corretamente."""
    parsed = urlparse(base_url)
    if not parsed.scheme:
        base_url = "https://" + base_url
    if not base_url.endswith("/"):
        base_url += "/"
    return urljoin(base_url, "access.log")


def parse_time_to_iso(ts: str) -> Optional[str]:
    """Converte timestamp CLF para ISO 8601 (UTC)."""
    fmt = "%d/%b/%Y:%H:%M:%S %z"
    try:
        dt_obj = dt.datetime.strptime(ts, fmt)
        return dt_obj.astimezone(dt.timezone.utc).isoformat()
    except Exception:
        return None


def split_request(req: str) -> Dict[str, str]:
    """Divide 'METHOD PATH PROTOCOL'."""
    method, path, proto = "", "", ""
    if req:
        parts = req.split()
        if len(parts) == 3:
            method, path, proto = parts
        elif len(parts) == 2:
            method, path = parts
        else:
            path = req
    return {"method": method.upper(), "path": path, "protocol": proto}


def count_suspicious_tokens(*texts: Optional[str]) -> int:
    """Conta ocorrências de tokens suspeitos (URL-decoding 2x)."""
    blob = " ".join([t for t in texts if t]) if texts else ""
    decoded = blob
    for _ in range(2):
        try:
            decoded = unquote_plus(decoded)
        except Exception:
            break
    low = decoded.lower()
    return sum(low.count(tk) for tk in SUSPICIOUS_TOKENS)


def parse_line(line: str) -> Optional[Dict[str, object]]:
    """Parseia uma linha CLF; retorna dict ou None se inválida."""
    m = CLF_RE.match(line)
    if not m:
        return None
    gd = m.groupdict()
    req = split_request(gd.get("request") or "")

    try:
        status = int(gd.get("status") or 0)
    except ValueError:
        status = 0

    size_raw = gd.get("size") or "-"
    size = int(size_raw) if size_raw.isdigit() else 0

    iso_ts = parse_time_to_iso(gd.get("time") or "")
    if not iso_ts:
        return None

    referer = gd.get("referer") or ""
    agent = gd.get("agent") or ""

    susp_count = count_suspicious_tokens(req["path"], referer)

    return {
        "ts": iso_ts,
        "ip": gd.get("ip") or "",
        "method": req["method"],
        "path": req["path"],
        "status": status,
        "bytes": size,
        "referer": referer,
        "user_agent": agent,
        "suspicious_token_count": susp_count,
        "has_suspicious_token": 1 if susp_count > 0 else 0,
    }


def iter_lines_from_url(url: str) -> Iterable[str]:
    """Baixa conteúdo de uma URL e itera as linhas (streaming)."""
    with requests.get(url, stream=True, timeout=TIMEOUT_S) as r:
        r.raise_for_status()
        for line in r.iter_lines(decode_unicode=True):
            if line is None:
                continue
            yield line.rstrip("\n")


def write_csv(rows: Iterable[Dict[str, object]], out_path: str) -> int:
    """Escreve CSV fixo; retorna número de linhas."""
    fields = [
        "ts",
        "ip",
        "method",
        "path",
        "status",
        "bytes",
        "referer",
        "user_agent",
        "suspicious_token_count",
        "has_suspicious_token",
    ]
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    count = 0
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            if not row:
                continue
            w.writerow({k: row.get(k, "") for k in fields})
            count += 1
    return count


def main():
    ap = argparse.ArgumentParser(
        description="Parser de /access.log a partir de uma URL-base (Nota C, minimalista)."
    )
    ap.add_argument(
        "--url", required=True, help="URL-base (ex.: https://seu-servidor.com)"
    )
    args = ap.parse_args()

    log_url = build_log_url(args.url)

    parsed_rows = []
    total_in = 0
    dropped = 0

    try:
        for line in iter_lines_from_url(log_url):
            total_in += 1
            rec = parse_line(line)
            if rec:
                parsed_rows.append(rec)
            else:
                dropped += 1
    except KeyboardInterrupt:
        print("\n[!] Interrompido pelo usuário.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"[ERRO] Falha ao ler {log_url}: {e}", file=sys.stderr)
        sys.exit(2)

    written = write_csv(parsed_rows, OUT_PATH)

    print(f"[OK] URL-base: {args.url}")
    print(f"[OK] Log requisitado: {log_url}")
    print(f"[OK] Linhas lidas: {total_in}")
    print(f"[OK] Linhas válidas: {written}  |  Descartadas: {dropped}")
    print(f"[OK] Saída: {OUT_PATH}")
    if written > 0:
        flagged = sum(1 for r in parsed_rows if r.get("has_suspicious_token") == 1)
        print(f"[OK] Registros com 'has_suspicious_token=1': {flagged}")


if __name__ == "__main__":
    main()
