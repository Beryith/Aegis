import asyncio
import json
import os
import aiohttp
import asyncpg
import nats
from datetime import datetime, timezone
from abc import ABC, abstractmethod
import sys
sys.path.append('/app')
sys.path.append('/home/krow/aegis/services')
from utils import connect_with_retry, run_with_retry
from logger import get_logger
from health import HealthServer

log = get_logger("ai")

DB_URL = os.getenv("DB_URL", "postgresql://aegis:aegis@127.0.0.1:5432/aegis")
NATS_URL = os.getenv("NATS_URL", "nats://aegis:aegis@localhost:4222")
CONFIG_PATH = os.path.expanduser("~/.aegis/config.json")
HEALTH_PORT = 9104

health = HealthServer("ai", HEALTH_PORT)

class AIProvider(ABC):
    @abstractmethod
    async def generate(self, prompt: str) -> str:
        pass

class OllamaProvider(AIProvider):
    def __init__(self, config: dict):
        self.url = config.get("url", "http://localhost:11434")
        self.model = config.get("model", "mistral")

    async def generate(self, prompt: str) -> str:
        try:
            async with aiohttp.ClientSession() as session:
                payload = {"model": self.model, "prompt": prompt, "stream": False}
                async with session.post(
                    f"{self.url}/api/generate",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=600)
                ) as resp:
                    if resp.status != 200:
                        log.error(f"Ollama erreur HTTP {resp.status}")
                        return ""
                    data = await resp.json()
                    return data.get("response", "").strip()
        except Exception as e:
            log.error(f"Erreur Ollama : {e}")
            return ""

class GroqProvider(AIProvider):
    def __init__(self, config: dict):
        self.api_key = config.get("api_key", "")
        self.model = config.get("model", "mixtral-8x7b-32768")

    async def generate(self, prompt: str) -> str:
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                payload = {
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 1000
                }
                async with session.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        log.error(f"Groq erreur HTTP {resp.status} : {body[:300]}")
                        return ""
                    data = await resp.json()
                    return data["choices"][0]["message"]["content"].strip()
        except Exception as e:
            log.error(f"Erreur Groq : {e}")
            return ""

class GeminiProvider(AIProvider):
    def __init__(self, config: dict):
        self.api_key = config.get("api_key", "")
        self.model = config.get("model", "gemini-1.5-flash")

    async def generate(self, prompt: str) -> str:
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
                payload = {"contents": [{"parts": [{"text": prompt}]}]}
                async with session.post(
                    url, json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status != 200:
                        log.error(f"Gemini erreur HTTP {resp.status}")
                        return ""
                    data = await resp.json()
                    return data["candidates"][0]["content"]["parts"][0]["text"].strip()
        except Exception as e:
            log.error(f"Erreur Gemini : {e}")
            return ""

class OpenAIProvider(AIProvider):
    def __init__(self, config: dict):
        self.api_key = config.get("api_key", "")
        self.model = config.get("model", "gpt-4o-mini")

    async def generate(self, prompt: str) -> str:
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                payload = {
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 1000
                }
                async with session.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers=headers, json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status != 200:
                        log.error(f"OpenAI erreur HTTP {resp.status}")
                        return ""
                    data = await resp.json()
                    return data["choices"][0]["message"]["content"].strip()
        except Exception as e:
            log.error(f"Erreur OpenAI : {e}")
            return ""

class AnthropicProvider(AIProvider):
    def __init__(self, config: dict):
        self.api_key = config.get("api_key", "")
        self.model = config.get("model", "claude-haiku-4-5-20251001")

    async def generate(self, prompt: str) -> str:
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json"
                }
                payload = {
                    "model": self.model,
                    "max_tokens": 1000,
                    "messages": [{"role": "user", "content": prompt}]
                }
                async with session.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=headers, json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status != 200:
                        log.error(f"Anthropic erreur HTTP {resp.status}")
                        return ""
                    data = await resp.json()
                    return data["content"][0]["text"].strip()
        except Exception as e:
            log.error(f"Erreur Anthropic : {e}")
            return ""

def load_config() -> dict:
    try:
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        log.error(f"Erreur chargement config : {e}")
        return {"ai": {"provider": "ollama", "providers": {"ollama": {"url": "http://localhost:11434", "model": "mistral"}}}}

def get_provider(config: dict) -> AIProvider:
    ai_config = config.get("ai", {})
    provider_name = ai_config.get("provider", "ollama")
    providers_config = ai_config.get("providers", {})
    provider_config = providers_config.get(provider_name, {})

    providers = {
        "ollama": OllamaProvider,
        "groq": GroqProvider,
        "gemini": GeminiProvider,
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
    }

    cls = providers.get(provider_name, OllamaProvider)
    log.info(f"Provider actif : {provider_name}")
    return cls(provider_config)

async def generate_one_recommendation(conn, provider: AIProvider, scan_id: str,
                                        title: str, findings: list) -> dict:
    """Génère une recommandation IA à partir d'une liste de findings ciblée."""
    findings_text = ""
    findings_summary = []
    for f in findings:
        line = f"- [{f['severity'].upper()}] {f['title']} (source: {f['source']}, host: {f['host']})"
        if f['description']:
            line += f"\n  Détail: {f['description'][:200]}"
        findings_text += line + "\n"
        findings_summary.append({"title": f['title'], "severity": f['severity']})

    prompt = f"""Tu es un expert en cybersécurité. Voici un groupe de résultats de scan liés entre eux (même thème de risque) :

{findings_text}

Réponds en français. Fournis une analyse structurée avec exactement ce format JSON et rien d'autre :
{{
  "priority": "immediate|short_term|medium_term|long_term",
  "title": "titre court de la recommandation principale",
  "context": "explication claire du risque en 2-3 phrases",
  "action": "liste des actions concrètes à entreprendre",
  "impact": "impact si rien n'est fait",
  "effort": "low|medium|high"
}}"""

    response = await provider.generate(prompt)
    if not response:
        log.error(f"Pas de réponse du provider pour le groupe : {title}")
        return None

    try:
        start = response.find("{")
        end = response.rfind("}") + 1
        if start == -1 or end == 0:
            log.error(f"Pas de JSON trouvé pour {title} : {response[:200]}")
            return None

        rec = json.loads(response[start:end])

        await run_with_retry(conn.execute, """
            INSERT INTO recommendations (scan_id, priority, title, findings_summary, recommendation, generated_by, generated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        """,
            scan_id,
            rec.get("priority", "medium_term"),
            rec.get("title", title),
            json.dumps(findings_summary),
            json.dumps({
                "context": rec.get("context", ""),
                "action": rec.get("action", ""),
                "impact": rec.get("impact", ""),
                "effort": rec.get("effort", "medium")
            }),
            "ai_layer",
            datetime.now(timezone.utc)
        )
        log.info(f"Recommandation stockée : {rec.get('title')} [{rec.get('priority')}]")
        return rec
    except json.JSONDecodeError as e:
        log.error(f"Erreur parsing JSON pour {title} : {e}")
        return None


async def generate_recommendation(scan_id: str, conn, provider: AIProvider):
    log.info(f"Génération pour le scan {scan_id}")

    # Récupère les groupes de corrélation identifiés par le Correlation Engine
    correlations = await conn.fetch("""
        SELECT id, title, metadata
        FROM findings
        WHERE scan_id = $1 AND source = 'correlation'
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END
    """, scan_id)

    if correlations:
        log.info(f"{len(correlations)} groupe(s) de corrélation trouvé(s) — génération de recommandations ciblées")

        for corr in correlations:
            meta = corr["metadata"] if isinstance(corr["metadata"], dict) else json.loads(corr["metadata"] or "{}")
            related_ids = meta.get("correlated_findings", [])

            if not related_ids:
                continue

            findings = await conn.fetch("""
                SELECT f.title, f.severity, f.source, f.description, a.value as host
                FROM findings f
                JOIN assets a ON f.asset_id = a.id
                WHERE f.id = ANY($1::uuid[])
            """, related_ids)

            if findings:
                await generate_one_recommendation(conn, provider, scan_id, corr["title"], findings)

        return

    # Fallback — aucune corrélation trouvée, on analyse tous les findings ensemble
    log.info("Aucune corrélation trouvée — génération d'une recommandation globale")
    findings = await conn.fetch("""
        SELECT f.title, f.severity, f.source, f.description, a.value as host
        FROM findings f
        JOIN assets a ON f.asset_id = a.id
        WHERE f.scan_id = $1
        ORDER BY
            CASE f.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END
    """, scan_id)

    if not findings:
        log.info("Aucun finding à analyser")
        return

    await generate_one_recommendation(conn, provider, scan_id, "Analyse globale", findings)


async def handle_ai_request(msg):
    data = json.loads(msg.data.decode())
    scan_id = data.get("scan_id")
    log.info(f"Tâche reçue — scan_id={scan_id}")
    health.set_check("last_task", True, f"scan_id={scan_id}")

    config = load_config()
    provider = get_provider(config)

    async def db_connect():
        return await asyncpg.connect(DB_URL)

    conn = await connect_with_retry(db_connect, "PostgreSQL")
    try:
        await generate_recommendation(scan_id, conn, provider)

        await conn.execute(
            "UPDATE scans SET status = $1, completed_at = $2 WHERE id = $3",
            "completed", datetime.now(timezone.utc), scan_id
        )
        log.info(f"Scan {scan_id} marqué comme terminé")
    except Exception as e:
        health.set_check("last_task", False, str(e))
        log.error(f"Erreur génération recommandation : {e}")
    finally:
        await conn.close()

async def main():
    log.info("Démarrage")
    config = load_config()
    provider_name = config.get("ai", {}).get("provider", "ollama")

    async def nats_connect():
        return await nats.connect(NATS_URL)

    nc = await connect_with_retry(nats_connect, "NATS")
    health.set_check("nats", True)
    log.info(f"Provider actif : {provider_name}")

    await nc.subscribe("aegis.ai.analyze", cb=handle_ai_request)
    log.info("En attente de tâches sur aegis.ai.analyze")

    health.set_ready()
    await health.start()

    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
