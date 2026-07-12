import asyncio
import logging

log = logging.getLogger(__name__)

async def connect_with_retry(connect_fn, service_name: str, max_retries: int = 10):
    """
    Tente de se connecter avec backoff exponentiel.
    Attend 1s, 2s, 4s, 8s... entre chaque tentative.
    """
    delay = 1
    for attempt in range(1, max_retries + 1):
        try:
            conn = await connect_fn()
            log.info(f"{service_name} connecté (tentative {attempt})")
            return conn
        except Exception as e:
            if attempt == max_retries:
                log.error(f"{service_name} — échec après {max_retries} tentatives : {e}")
                raise
            log.warning(f"{service_name} — tentative {attempt}/{max_retries} échouée : {e}")
            log.info(f"Nouvelle tentative dans {delay}s...")
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30)

async def run_with_retry(fn, *args, max_retries: int = 3, **kwargs):
    """
    Exécute une fonction avec retry en cas d'erreur.
    """
    delay = 1
    for attempt in range(1, max_retries + 1):
        try:
            return await fn(*args, **kwargs)
        except Exception as e:
            if attempt == max_retries:
                log.error(f"Échec après {max_retries} tentatives : {e}")
                raise
            log.warning(f"Tentative {attempt}/{max_retries} échouée : {e}")
            await asyncio.sleep(delay)
            delay = min(delay * 2, 10)
