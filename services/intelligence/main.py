import asyncio
import json
import logging
import aiohttp
import whois
import asyncpg
import nats
from datetime import datetime, timezone
import sys
sys.path.append('/home/krow/aegis/services')
from utils import connect_with_retry, run_with_retry

logging.basicConfig(level=logging.INFO, format='[intelligence] %(message)s')
log = logging.getLogger(__name__)

DB_URL = "postgresql://aegis:aegis@127.0.0.1:5432/aegis"
NATS_URL = "nats://aegis:aegis@localhost:4222"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

async def lookup_cve(service: str, version: str) -> list:
    if not service or not version:
        return []
    keyword = f"{service} {version}"
    url = f"{NVD_API}?keywordSearch={keyword}&resultsPerPage=5"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
                cves = []
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "")
                    descriptions = cve.get("descriptions", [])
                    desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
                    metrics = cve.get("metrics", {})
                    score = None
                    severity = "unknown"
                    if "cvssMetricV31" in metrics:
                        cvss = metrics["cvssMetricV31"][0]["cvssData"]
                        score = cvss.get("baseScore")
                        severity = cvss.get("baseSeverity", "unknown").lower()
                    elif "cvssMetricV2" in metrics:
                        cvss = metrics["cvssMetricV2"][0]["cvssData"]
                        score = cvss.get("baseScore")
                        severity = "medium"
                    cves.append({
                        "cve_id": cve_id,
                        "description": desc[:300],
                        "score": score,
                        "severity": severity
                    })
                return cves
    except Exception as e:
        log.warning(f"Erreur CVE lookup pour {keyword}: {e}")
        return []

async def lookup_whois(host: str) -> dict:
    try:
        w = whois.whois(host)
        return {
            "registrar": str(w.registrar) if w.registrar else None,
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "country": str(w.country) if w.country else None,
        }
    except Exception as e:
        log.warning(f"Erreur WHOIS pour {host}: {e}")
        return {}

async def store_finding(conn, scan_id: str, asset_id: str, cve: dict, original_title: str):
    severity_map = {
        "critical": "critical", "high": "high",
        "medium": "medium", "low": "low", "unknown": "info"
    }
    severity = severity_map.get(cve["severity"], "info")
    title = f"{cve['cve_id']} détecté — {original_title}"
    await conn.execute("""
        INSERT INTO findings (asset_id, scan_id, source, type, title, description, severity, confidence, status, discovered_at, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    """,
        asset_id, scan_id, "intelligence", "vulnerability",
        title, cve["description"], severity, 0.80, "open",
        datetime.now(timezone.utc), json.dumps(cve)
    )
    log.info(f"CVE stockée : {title} [{severity}]")

async def handle_intelligence_request(msg):
    data = json.loads(msg.data.decode())
    scan_id = data.get("scan_id")
    asset_id = data.get("asset_id")
    host = data.get("host")
    service = data.get("service")
    version = data.get("version")

    log.info(f"Enrichissement — {host} {service} {version}")

    async def db_connect():
        return await asyncpg.connect(DB_URL)

    conn = await connect_with_retry(db_connect, "PostgreSQL")
    try:
        cves = await lookup_cve(service, version)
        log.info(f"{len(cves)} CVE(s) trouvée(s) pour {service} {version}")
        for cve in cves:
            await run_with_retry(store_finding, conn, scan_id, asset_id, cve, f"{service} {version}")

        whois_data = await lookup_whois(host)
        if whois_data:
            await conn.execute("""
                UPDATE assets SET metadata = metadata || $1 WHERE id = $2
            """, json.dumps({"whois": whois_data}), asset_id)
            log.info(f"WHOIS stocké pour {host}")
    finally:
        await conn.close()

async def main():
    log.info("Démarrage")

    async def nats_connect():
        return await nats.connect(NATS_URL)

    nc = await connect_with_retry(nats_connect, "NATS")
    await nc.subscribe("aegis.intelligence.enrich", cb=handle_intelligence_request)
    log.info("En attente de tâches sur aegis.intelligence.enrich")

    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
