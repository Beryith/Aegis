FROM python:3.13-slim

WORKDIR /app

RUN pip install nats-py asyncpg aiohttp --no-cache-dir

COPY services/intelligence/correlator.py ./main.py
COPY services/utils.py ./
COPY services/logger.py ./
COPY services/health.py ./

EXPOSE 9103

CMD ["python3", "main.py"]
