import asyncio
import json
import logging
from aiohttp import web

log = logging.getLogger(__name__)

class HealthServer:
    def __init__(self, service: str, port: int):
        self.service = service
        self.port = port
        self.status = "starting"
        self.checks = {}

    def set_ready(self):
        self.status = "ok"

    def set_check(self, name: str, ok: bool, detail: str = ""):
        self.checks[name] = {"ok": ok, "detail": detail}

    async def handle_health(self, request):
        all_ok = self.status == "ok" and all(
            c["ok"] for c in self.checks.values()
        )
        body = {
            "service": self.service,
            "status": "ok" if all_ok else "degraded",
            "checks": self.checks
        }
        status = 200 if all_ok else 503
        return web.Response(
            text=json.dumps(body),
            content_type="application/json",
            status=status
        )

    async def start(self):
        app = web.Application()
        app.router.add_get("/health", self.handle_health)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", self.port)
        await site.start()
        log.info(f"Healthcheck disponible sur :{self.port}/health")
