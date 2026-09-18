import json
import urllib.error
import urllib.request
from datetime import datetime

LIVE_VULNS_CACHE = []
LIVE_VULNS_ERROR = None
LIVE_VULNS_FETCHED_AT = None
CACHE_TTL_SECONDS = 1800


def _fetch_live_vulnerabilities():
    records = []
    errors = []
    sources = [
        ("CISA KEV", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
        ("NVD", "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5"),
    ]
    for source_name, source_url in sources:
        try:
            req = urllib.request.Request(source_url, headers={"User-Agent": "CyberControl/1.0"})
            # source_url vem exclusivamente da lista de endpoints HTTPS definidos no código.
            with urllib.request.urlopen(req, timeout=15) as response:  # nosec B310
                payload = json.loads(response.read().decode("utf-8"))

            if source_name == "CISA KEV":
                for item in payload.get("vulnerabilities", []):
                    cve_id = item.get("cveID") or ""
                    records.append({
                        "id": cve_id,
                        "title": item.get("vulnerabilityName") or cve_id or "Vulnerabilidade conhecida",
                        "description": item.get("shortDescription") or item.get("notes") or "Descrição não informada.",
                        "source": source_name,
                        "severity": "Alta" if item.get("knownRansomwareCampaignUse") == "Known" else "Média",
                        "kev": True,
                        "known_ransomware": item.get("knownRansomwareCampaignUse") == "Known",
                        "due_date": item.get("dueDate"),
                        "link": f"https://www.cve.org/CVERecord?id={cve_id}" if cve_id else "#",
                    })
            else:
                for item in payload.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = cve.get("id") or ""
                    descriptions = cve.get("descriptions", []) or []
                    english = next((d for d in descriptions if d.get("lang") == "en"), None)
                    description = (english or (descriptions[0] if descriptions else {})).get("value", "Descrição não informada.")
                    metrics = cve.get("metrics", {}) or {}
                    cvss = None
                    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
                        entries = metrics.get(key) or []
                        if entries:
                            cvss = entries[0].get("cvssData", {}).get("baseScore")
                            break
                    severity = "Alta"
                    if cvss is not None:
                        score = float(cvss)
                        severity = "Nenhuma" if score == 0 else "Baixa" if score < 4 else "Média" if score < 7 else "Alta" if score < 9 else "Crítica"
                    records.append({
                        "id": cve_id,
                        "title": cve_id or "Vulnerabilidade recente",
                        "description": description,
                        "source": source_name,
                        "severity": severity,
                        "cvss": cvss,
                        "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "#",
                    })
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{source_name}: {exc}")

    unique_records = []
    seen_ids = set()
    for item in records:
        if item["id"] and item["id"] in seen_ids:
            continue
        unique_records.append(item)
        if item["id"]:
            seen_ids.add(item["id"])
    return unique_records, "; ".join(errors) if errors else None


def refresh_live_vulnerabilities(force=False, limit=8, search_term="", source_filter="", severity_filter=""):
    global LIVE_VULNS_CACHE, LIVE_VULNS_ERROR, LIVE_VULNS_FETCHED_AT
    cache_is_fresh = False
    if LIVE_VULNS_FETCHED_AT:
        cache_is_fresh = (datetime.now() - LIVE_VULNS_FETCHED_AT).total_seconds() < CACHE_TTL_SECONDS
    if force or not cache_is_fresh:
        LIVE_VULNS_CACHE, LIVE_VULNS_ERROR = _fetch_live_vulnerabilities()
        LIVE_VULNS_FETCHED_AT = datetime.now()

    records = list(LIVE_VULNS_CACHE)
    if search_term:
        term = search_term.strip().lower()
        records = [item for item in records if term in (item.get("title") or "").lower() or term in (item.get("description") or "").lower() or term in (item.get("source") or "").lower()]
    if source_filter:
        records = [item for item in records if (item.get("source") or "").lower() == source_filter.lower()]
    if severity_filter:
        records = filter_live_vulnerabilities(records, severity_filter=severity_filter)
    return records[:limit], LIVE_VULNS_ERROR


def filter_live_vulnerabilities(items, severity_filter=""):
    if not severity_filter:
        return list(items)
    severity_filter = severity_filter.lower()
    return [item for item in items if (item.get("severity") or "").lower() == severity_filter]


def summarize_live_vulnerabilities(items):
    summary = {"total": len(items), "by_source": {}, "by_severity": {}}
    for item in items:
        source = item.get("source", "Outros")
        severity = item.get("severity", "Média")
        summary["by_source"][source] = summary["by_source"].get(source, 0) + 1
        summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
    return summary
