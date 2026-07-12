import asyncio
import json
import logging
import nmap
import asyncpg
import nats
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format='[discovery] %(message)s')
log = logging.getLogger(__name__)

DB_URL = "postgresql://aegis:aegis@127.0.0.1:5432/aegis"
NATS_URL = "nats://aegis:aegis@localhost:4222"

async def scan_target(target: str) -> list:
    log.info(f"Scan de {target}")
    nm = nmap.PortScanner()
    nm.scan(target, arguments="-sV --open -T4")

    findings = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                service = nm[host][proto][port]
                findings.append({
                    "host": host,
                    "port": port,
                    "protocol": proto,
                    "state": service["state"],
                    "service": service["name"],
                    "version": service.get("version", ""),
                })

    return findings

async def store_finding(conn, scan_id: str, asset_id: str, finding: dict):
    title = f"Port {finding['port']}/{finding['protocol']} ouvert — {finding['service']}"
    await conn.execute("""
        INSERT INTO findings (asset_id, scan_id, source, type, title, severity, confidence, status, discovered_at, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    """,
        asset_id,
        scan_id,
        "discovery",
        "open_port",
        title,
        "info",
        0.95,
        "open",
        datetime.now(timezone.utc),
        json.dumps(finding)
    )
    log.info(f"Finding stocké : {title}")

async def store_asset(conn, host: str) -> str:
    row = await conn.fetchrow("""
        INSERT INTO assets (type, value, criticality, exposure, discovered_at, discovered_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT DO NOTHING
        RETURNING id
    """, "host", host, "medium", "internet", datetime.now(timezone.utc), "discovery")

    if row:
        return str(row["id"])

    row = await conn.fetchrow("SELECT id FROM assets WHERE value = $1", host)
    return str(row["id"])

async def handle_scan_request(msg):
    data = json.loads(msg.data.decode())
    scan_id = data.get("scan_id")
    target = data.get("target")

    log.info(f"Tâche reçue — scan_id={scan_id} target={target}")

    conn = await asyncpg.connect(DB_URL)
    try:
        findings = await scan_target(target)
        log.info(f"{len(findings)} findings trouvés")

        for finding in findings:
            asset_id = await store_asset(conn, finding["host"])
            await store_finding(conn, scan_id, asset_id, finding)

    finally:
        await conn.close()

async def main():
    log.info("Démarrage")
    nc = await nats.connect(NATS_URL)
    log.info("NATS connecté")

    await nc.subscribe("aegis.discovery.scan", cb=handle_scan_request)
    log.info("En attente de tâches sur aegis.discovery.scan")

    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
