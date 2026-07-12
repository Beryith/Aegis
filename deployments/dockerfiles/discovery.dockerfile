FROM python:3.13-slim

RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install nats-py asyncpg python-nmap aiohttp --no-cache-dir

COPY services/discovery/main.py ./
COPY services/utils.py ./
COPY services/logger.py ./
COPY services/health.py ./

EXPOSE 9101

CMD ["python3", "main.py"]
