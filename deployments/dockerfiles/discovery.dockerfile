FROM python:3.13-slim

RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/discovery/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt --no-cache-dir

COPY services/discovery/main.py ./
COPY services/utils.py ./
COPY services/logger.py ./
COPY services/health.py ./

EXPOSE 9101

CMD ["python3", "main.py"]
