import asyncio
import json
import logging
import asyncpg
import nats
from datetime import datetime, timezone
import sys
sys.path.append('/home/krow/aegis/services')
from utils import connect_with_retry, run_with_retry

logging.basicConfig(level=logging.INFO, format='[correlator] %(message)s')
log = logging.getLogger(__name__)

DB_URL = "postgresql://aegis:aegis@127.0.0.1:5432/aegis"
NATS_URL = "nats://aegis:aegis@localhost:4222"

ADMIN_SERVICES = ["ssh", "rdp", "telnet", "ftp", "vnc", "mysql", "postgresql", "mongodb"]

async def correlate(scan_id: str, conn):
    log.info(f"Corrélation du scan {scan_id}")

    findings = await conn.fetch("""
        SELECT f.id, f.asset_id, f.source, f.type, f.title,
               f.severity, f.metadata, a.value as host
        FROM findings f
        JOIN assets a ON f.asset_id = a.id
        WHERE f.scan_id = $1
    """, scan_id)

    if not findings:
        log.info("Aucun finding à corréler")
        return

    assets = {}
    for f in findings:
        aid = str(f["asset_id"])
        if aid not in assets:
            assets[aid] = {"host": f["host"], "findings": []}
        assets[aid]["findings"].append(dict(f))

    correlations = []

    for asset_id, data in assets.items():
        host = data["host"]
        findings_list = data["findings"]

        open_ports = [f for f in findings_list if f["type"] == "open_port"]
        vulnerabilities = [f for f in findings_list if f["type"] == "vulnerability"]

        # Règle 1 — Port ouvert + CVE trouvée
        if open_ports and vulnerabilities:
            correlations.append({
                "asset_id": asset_id,
                "host": host,
                "severity": "high",
                "title": f"Service vulnérable exposé sur {host}",
                "description": f"{len(vulnerabilities)} CVE(s) trouvée(s) sur {len(open_ports)} port(s) ouvert(s)",
                "finding_ids": [f["id"] for f in open_ports + vulnerabilities]
            })

        # Règle 2 — Service d'administration exposé
        admin_ports = []
        for f in open_ports:
            meta = f["metadata"] if isinstance(f["metadata"], dict) else json.loads(f["metadata"] or "{}")
            service = meta.get("service", "")
            if service in ADMIN_SERVICES:
                admin_ports.append(f)

        if admin_ports:
            services = [json.loads(f["metadata"] or "{}").get("service", "") if isinstance(f["metadata"], str) else f["metadata"].get("service", "") for f in admin_ports]
            correlations.append({
                "asset_id": asset_id,
                "host": host,
                "severity": "medium",
                "title": f"Service d'administration exposé sur {host}",
                "description": f"Services sensibles détectés : {', '.join(services)}",
                "finding_ids": [f["id"] for f in admin_ports]
            })

        # Règle 3 — Surface d'attaque élargie
        if len(open_ports) > 3:
            correlations.append({
                "asset_id": asset_id,
                "host": host,
                "severity": "medium",
                "title": f"Surface d'attaque élargie sur {host}",
                "description": f"{len(open_ports)} ports ouverts détectés",
                "finding_ids": [f["id"] for f in open_ports]
            })

    for corr in correlations:
        await run_with_retry(conn.execute, """
            INSERT INTO findings (asset_id, scan_id, source, type, title, description, severity, confidence, status, discovered_at, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        """,
            corr["asset_id"], scan_id, "correlation", "exposure",
            corr["title"], corr["description"], corr["severity"],
            0.90, "open", datetime.now(timezone.utc),
            json.dumps({"correlated_findings": [str(fid) for fid in corr["finding_ids"]]})
        )
        log.info(f"Corrélation stockée : {corr['title']} [{corr['severity']}]")

    log.info(f"{len(correlations)} corrélation(s) générée(s)")

async def handle_correlate_request(msg):
    data = json.loads(msg.data.decode())
    scan_id = data.get("scan_id")

    async def db_connect():
        return await asyncpg.connect(DB_URL)

    conn = await connect_with_retry(db_connect, "PostgreSQL")
    try:
        await correlate(scan_id, conn)
    finally:
        await conn.close()

async def main():
    log.info("Démarrage")

    async def nats_connect():
        return await nats.connect(NATS_URL)

    nc = await nats.connect(NATS_URL)
    nc = await connect_with_retry(nats_connect, "NATS")
    await nc.subscribe("aegis.correlation.run", cb=handle_correlate_request)
    log.info("En attente de tâches sur aegis.correlation.run")

    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
