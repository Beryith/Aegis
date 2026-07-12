FROM python:3.13-slim

RUN apt-get update && apt-get install -y whois && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install nats-py asyncpg aiohttp python-whois --no-cache-dir

COPY services/intelligence/main.py ./
COPY services/utils.py ./
COPY services/logger.py ./
COPY services/health.py ./

EXPOSE 9102

CMD ["python3", "main.py"]
