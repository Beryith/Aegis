import asyncio
import json
import os
import nmap
import asyncpg
import nats
from datetime import datetime, timezone
import sys
sys.path.append('/app')
sys.path.append('/home/krow/aegis/services')
from utils import connect_with_retry, run_with_retry
from logger import get_logger
from health import HealthServer

log = get_logger("discovery")

DB_URL = os.getenv("DB_URL", "postgresql://aegis:aegis@127.0.0.1:5432/aegis")
NATS_URL = os.getenv("NATS_URL", "nats://aegis:aegis@localhost:4222")
HEALTH_PORT = 9101

nc = None
health = HealthServer("discovery", HEALTH_PORT)

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
        asset_id, scan_id, "discovery", "open_port", title,
        "info", 0.95, "open", datetime.now(timezone.utc), json.dumps(finding)
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
    health.set_check("last_task", True, f"scan_id={scan_id}")

    async def db_connect():
        return await asyncpg.connect(DB_URL)

    conn = await connect_with_retry(db_connect, "PostgreSQL")
    try:
        findings = await scan_target(target)
        log.info(f"{len(findings)} findings trouvés")

        for finding in findings:
            asset_id = await run_with_retry(store_asset, conn, finding["host"])
            await run_with_retry(store_finding, conn, scan_id, asset_id, finding)

            if finding.get("service") and finding.get("version"):
                payload = json.dumps({
                    "scan_id": scan_id,
                    "asset_id": asset_id,
                    "host": finding["host"],
                    "service": finding["service"],
                    "version": finding["version"],
                }).encode()
                await nc.publish("aegis.intelligence.enrich", payload)
                log.info(f"Envoyé à intelligence : {finding['service']} {finding['version']}")

        await nc.publish("aegis.correlation.run", json.dumps({"scan_id": scan_id}).encode())
        log.info(f"Corrélation déclenchée pour le scan {scan_id}")

    except Exception as e:
        health.set_check("last_task", False, str(e))
        log.error(f"Erreur traitement scan {scan_id} : {e}")
    finally:
        await conn.close()

async def main():
    global nc

    log.info("Démarrage")

    async def nats_connect():
        return await nats.connect(NATS_URL)

    nc = await connect_with_retry(nats_connect, "NATS")
    health.set_check("nats", True)

    await nc.subscribe("aegis.discovery.scan", cb=handle_scan_request)
    log.info("En attente de tâches sur aegis.discovery.scan")

    health.set_ready()
    await health.start()

    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
