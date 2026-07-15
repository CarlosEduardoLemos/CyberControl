import json
import urllib.error
import urllib.request
from datetime import datetime

LIVE_VULNS_CACHE = []
LIVE_VULNS_ERROR = None
LIVE_VULNS_FETCHED_AT = None


def refresh_live_vulnerabilities(force=False, limit=8, search_term="", source_filter="", severity_filter=""):
    global LIVE_VULNS_CACHE, LIVE_VULNS_ERROR, LIVE_VULNS_FETCHED_AT

    if not force and LIVE_VULNS_CACHE and LIVE_VULNS_FETCHED_AT:
        age_seconds = (datetime.now() - LIVE_VULNS_FETCHED_AT).total_seconds()
        if age_seconds < 1800:
            return LIVE_VULNS_CACHE, LIVE_VULNS_ERROR

    records = []
    errors = []
    sources = [
        ("CISA KEV", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
        ("NVD", "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5"),
    ]

    for source_name, source_url in sources:
        try:
            req = urllib.request.Request(source_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as response:
                payload = json.loads(response.read().decode("utf-8"))

            if source_name == "CISA KEV":
                for item in payload.get("vulnerabilities", []):
                    cve_id = item.get("cveID") or ""
                    records.append({
                        "id": cve_id,
                        "title": item.get("vulnerabilityName") or cve_id or "Vulnerabilidade conhecida",
                        "description": item.get("shortDescription") or item.get("notes") or "Descrição não informada.",
                        "source": source_name,
                        "severity": "Alta" if item.get("knownRansomwareCampaignUse") else "Média",
                        "link": f"https://www.cve.org/CVERecord?id={cve_id}" if cve_id else "#",
                    })
            else:
                for item in payload.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = cve.get("id") or ""
                    descriptions = cve.get("descriptions", []) or []
                    description = descriptions[0].get("value", "") if descriptions else "Descrição não informada."
                    records.append({
                        "id": cve_id,
                        "title": cve_id or "Vulnerabilidade recente",
                        "description": description,
                        "source": source_name,
                        "severity": "Alta",
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
        seen_ids.add(item["id"])

    if search_term:
        term = search_term.strip().lower()
        filtered = [
            item for item in unique_records
            if term in (item.get("title") or "").lower()
            or term in (item.get("description") or "").lower()
            or term in (item.get("source") or "").lower()
        ]
        unique_records = filtered

    if source_filter:
        unique_records = [
            item for item in unique_records
            if (item.get("source") or "").lower() == source_filter.lower()
        ]

    if severity_filter:
        unique_records = filter_live_vulnerabilities(unique_records, severity_filter=severity_filter)

    LIVE_VULNS_CACHE = unique_records[:limit]
    LIVE_VULNS_ERROR = "; ".join(errors) if errors else None
    LIVE_VULNS_FETCHED_AT = datetime.now()
    return LIVE_VULNS_CACHE, LIVE_VULNS_ERROR


def filter_live_vulnerabilities(items, severity_filter=""):
    if not severity_filter:
        return list(items)

    severity_filter = severity_filter.lower()
    return [
        item for item in items
        if (item.get("severity") or "").lower() == severity_filter
    ]


def summarize_live_vulnerabilities(items):
    summary = {
        "total": len(items),
        "by_source": {},
        "by_severity": {},
    }

    for item in items:
        source = item.get("source", "Outros")
        severity = item.get("severity", "Média")
        summary["by_source"][source] = summary["by_source"].get(source, 0) + 1
        summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1

    return summary
