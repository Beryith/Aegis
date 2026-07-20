import asyncio
import json
import os
import aiohttp
import whois
import asyncpg
import nats
from datetime import datetime, timezone
import sys
sys.path.append('/app')
sys.path.append('/home/krow/aegis/services')
from utils import connect_with_retry, run_with_retry
from logger import get_logger
from health import HealthServer
from cpe_mapper import build_cpe_match_string, extract_version
from update_exploitdb import fetch_csv, index_exploits

nc = None

log = get_logger("intelligence")

DB_URL = os.getenv("DB_URL", "postgresql://aegis:aegis@127.0.0.1:5432/aegis")
NATS_URL = os.getenv("NATS_URL", "nats://aegis:aegis@localhost:4222")
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Optionnelle : sans clé, l'API NVD publique limite à 5 requêtes/30s, ce qui
# devient le goulot d'étranglement principal sur un scan avec beaucoup de
# services. Une clé gratuite (https://nvd.nist.gov/developers/request-an-api-key)
# relève la limite à 50 requêtes/30s.
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
HEALTH_PORT = 9102

health = HealthServer("intelligence", HEALTH_PORT)

async def _query_nvd(url: str) -> list:
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 404:
                return []
            if resp.status != 200:
                log.warning(f"NVD erreur HTTP {resp.status}")
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

async def lookup_cve(service: str, version: str) -> list:
    if not service or not version:
        return []

    # Tentative 1 — recherche précise par CPE
    cpe_match = build_cpe_match_string(service, version)
    if cpe_match:
        url = f"{NVD_API}?virtualMatchString={cpe_match}&resultsPerPage=10"
        try:
            cves = await _query_nvd(url)
            if cves:
                log.info(f"Match CPE réussi : {cpe_match} → {len(cves)} CVE(s)")
                return cves
            log.info(f"Match CPE sans résultat : {cpe_match} — fallback keyword")
        except Exception as e:
            log.warning(f"Erreur CPE lookup pour {cpe_match}: {e}")

    # Tentative 2 — fallback recherche par mot-clé (moins précis mais plus permissif)
    clean_version = extract_version(version)
    keyword = f"{service} {clean_version}".strip()
    url = f"{NVD_API}?keywordSearch={keyword}&resultsPerPage=5"
    try:
        cves = await _query_nvd(url)
        if cves:
            log.info(f"Match keyword réussi : {keyword} → {len(cves)} CVE(s)")
        return cves
    except Exception as e:
        log.warning(f"Erreur keyword lookup pour {keyword}: {e}")
        return []

async def lookup_whois(host: str) -> dict:
    try:
        # whois.whois() est une bibliothèque synchrone (socket bloquant) — on la
        # délègue à un thread pour ne pas geler la boucle asyncio, avec un timeout
        # au cas où le serveur WHOIS de la cible ne répond jamais.
        loop = asyncio.get_running_loop()
        w = await asyncio.wait_for(
            loop.run_in_executor(None, whois.whois, host),
            timeout=10
        )
        return {
            "registrar": str(w.registrar) if w.registrar else None,
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "country": str(w.country) if w.country else None,
        }
    except asyncio.TimeoutError:
        log.warning(f"Timeout WHOIS pour {host}")
        return {}
    except Exception as e:
        log.warning(f"Erreur WHOIS pour {host}: {e}")
        return {}

async def check_public_exploit(conn, cve_id: str) -> dict:
    """
    Vérifie si un exploit public est référencé dans la base exploit-db locale
    pour la CVE donnée.
    """
    row = await conn.fetchrow("""
        SELECT edb_id, title, exploit_type, verified
        FROM exploit_db
        WHERE $1 = ANY(cve_ids)
        ORDER BY verified DESC
        LIMIT 1
    """, cve_id)

    if row:
        return {
            "exploit_available": True,
            "edb_id": row["edb_id"],
            "exploit_title": row["title"],
            "exploit_type": row["exploit_type"],
            "verified": row["verified"]
        }
    return {"exploit_available": False}


async def store_finding(conn, scan_id: str, asset_id: str, cve: dict, original_title: str):
    severity_map = {
        "critical": "critical", "high": "high",
        "medium": "medium", "low": "low", "unknown": "info"
    }
    severity = severity_map.get(cve["severity"], "info")

    exploit_info = await check_public_exploit(conn, cve["cve_id"])

    # Un exploit public disponible élève la sévérité effective d'un cran
    # (une CVE "medium" avec exploit public est plus urgente qu'une "medium" théorique)
    effective_severity = severity
    if exploit_info["exploit_available"]:
        escalation = {"info": "low", "low": "medium", "medium": "high", "high": "critical"}
        effective_severity = escalation.get(severity, severity)

    title = f"{cve['cve_id']} détecté — {original_title}"
    if exploit_info["exploit_available"]:
        title += " ⚠ EXPLOIT PUBLIC DISPONIBLE"

    metadata = {**cve, "exploit": exploit_info}

    await conn.execute("""
        INSERT INTO findings (asset_id, scan_id, source, type, title, description, severity, confidence, status, discovered_at, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    """,
        asset_id, scan_id, "intelligence", "vulnerability",
        title, cve["description"], effective_severity, 0.80, "open",
        datetime.now(timezone.utc), json.dumps(metadata)
    )

    if exploit_info["exploit_available"]:
        log.warning(f"CVE avec exploit public : {title} [{effective_severity}]")
    else:
        log.info(f"CVE stockée : {title} [{effective_severity}]")

async def handle_intelligence_request(msg):
    data = json.loads(msg.data.decode())
    scan_id = data.get("scan_id")
    asset_id = data.get("asset_id")
    host = data.get("host")
    service = data.get("service")
    version = data.get("version")

    log.info(f"Enrichissement — {host} {service} {version}")
    health.set_check("last_task", True, f"scan_id={scan_id}")

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

        # Décrémente le compteur de tâches en attente pour ce scan.
        # Quand il atteint 0, TOUTES les tâches d'enrichissement sont terminées
        # et on peut déclencher la corrélation en toute sécurité.
        row = await conn.fetchrow("""
            UPDATE scans
            SET pending_enrichments = pending_enrichments - 1
            WHERE id = $1
            RETURNING pending_enrichments
        """, scan_id)

        if row and row["pending_enrichments"] <= 0:
            await nc.publish("aegis.correlation.run", json.dumps({"scan_id": scan_id}).encode())
            log.info(f"Toutes les tâches d'enrichissement terminées — corrélation déclenchée pour {scan_id}")

    except Exception as e:
        health.set_check("last_task", False, str(e))
        log.error(f"Erreur enrichissement : {e}")
    finally:
        await conn.close()

async def handle_update_exploitdb_request(msg):
    log.info("Demande de mise à jour exploit-db reçue")

    async def db_connect():
        return await asyncpg.connect(DB_URL)

    conn = await connect_with_retry(db_connect, "PostgreSQL")
    try:
        csv_text = await fetch_csv()
        await index_exploits(csv_text, conn)

        row = await conn.fetchrow("SELECT last_updated, total_entries FROM exploit_db_meta WHERE id = 1")
        response = {
            "success": True,
            "total_entries": row["total_entries"],
            "last_updated": row["last_updated"].isoformat()
        }
        log.info(f"Base exploit-db mise à jour : {row['total_entries']} entrées")
    except Exception as e:
        log.error(f"Erreur mise à jour exploit-db : {e}")
        response = {"success": False, "error": str(e)}
    finally:
        await conn.close()

    await msg.respond(json.dumps(response).encode())

async def main():
    log.info("Démarrage")

    global nc

    async def nats_connect():
        return await nats.connect(NATS_URL)

    nc = await connect_with_retry(nats_connect, "NATS")
    health.set_check("nats", True)

    await nc.subscribe("aegis.intelligence.enrich", cb=handle_intelligence_request)
    await nc.subscribe("aegis.intel.update_exploitdb", cb=handle_update_exploitdb_request)
    log.info("En attente de tâches sur aegis.intelligence.enrich")

    health.set_ready()
    await health.start()

    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
