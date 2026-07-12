import asyncio
import json
import os
import asyncpg
import nats
from datetime import datetime, timezone
import sys
sys.path.append('/app')
sys.path.append('/home/krow/aegis/services')
from utils import connect_with_retry, run_with_retry
from logger import get_logger
from health import HealthServer

log = get_logger("correlator")

DB_URL = os.getenv("DB_URL", "postgresql://aegis:aegis@127.0.0.1:5432/aegis")
NATS_URL = os.getenv("NATS_URL", "nats://aegis:aegis@localhost:4222")
HEALTH_PORT = 9103

ADMIN_SERVICES = ["ssh", "rdp", "telnet", "ftp", "vnc", "mysql", "postgresql", "mongodb"]

nc = None
health = HealthServer("correlator", HEALTH_PORT)

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

    def get_meta(f):
        return f["metadata"] if isinstance(f["metadata"], dict) else json.loads(f["metadata"] or "{}")

    for asset_id, data in assets.items():
        host = data["host"]
        findings_list = data["findings"]

        open_ports = [f for f in findings_list if f["type"] == "open_port"]
        vulnerabilities = [f for f in findings_list if f["type"] == "vulnerability"]

        # Règle 1 — Port ouvert + CVE trouvée, groupées PAR SERVICE
        if open_ports and vulnerabilities:
            services_with_ports = {get_meta(f).get("service", "unknown") for f in open_ports}

            for service_name in services_with_ports:
                service_vulns = [
                    v for v in vulnerabilities
                    if service_name.lower() in v["title"].lower()
                ]
                service_ports = [
                    p for p in open_ports
                    if get_meta(p).get("service", "unknown") == service_name
                ]

                if service_vulns:
                    exploit_count = sum(
                        1 for v in service_vulns
                        if get_meta(v).get("exploit", {}).get("exploit_available")
                    )
                    severity = "critical" if exploit_count > 0 else "high"

                    correlations.append({
                        "asset_id": asset_id,
                        "host": host,
                        "severity": severity,
                        "title": f"Service {service_name} vulnérable exposé sur {host}",
                        "description": f"{len(service_vulns)} CVE(s) trouvée(s) sur le service {service_name}"
                                        + (f", dont {exploit_count} avec exploit public disponible" if exploit_count else ""),
                        "finding_ids": [f["id"] for f in service_ports + service_vulns]
                    })

        # Règle 2 — Service d'administration exposé
        admin_ports = []
        for f in open_ports:
            meta = get_meta(f)
            service = meta.get("service", "")
            if service in ADMIN_SERVICES:
                admin_ports.append(f)

        if admin_ports:
            services = [get_meta(f).get("service", "") for f in admin_ports]
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

    health.set_check("last_task", True, f"scan_id={scan_id}")

    async def db_connect():
        return await asyncpg.connect(DB_URL)

    conn = await connect_with_retry(db_connect, "PostgreSQL")
    try:
        await correlate(scan_id, conn)
        await nc.publish("aegis.ai.analyze", json.dumps({"scan_id": scan_id}).encode())
        log.info(f"Analyse IA déclenchée pour le scan {scan_id}")
    except Exception as e:
        health.set_check("last_task", False, str(e))
        log.error(f"Erreur corrélation : {e}")
    finally:
        await conn.close()

async def main():
    global nc
    log.info("Démarrage")

    async def nats_connect():
        return await nats.connect(NATS_URL)

    nc = await connect_with_retry(nats_connect, "NATS")
    health.set_check("nats", True)

    await nc.subscribe("aegis.correlation.run", cb=handle_correlate_request)
    log.info("En attente de tâches sur aegis.correlation.run")

    health.set_ready()
    await health.start()

    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
