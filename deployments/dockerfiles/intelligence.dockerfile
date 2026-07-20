FROM python:3.13-slim

RUN apt-get update && apt-get install -y whois && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/intelligence/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt --no-cache-dir

COPY services/intelligence/main.py ./
COPY services/intelligence/update_exploitdb.py ./
COPY services/utils.py ./
COPY services/logger.py ./
COPY services/health.py ./
COPY services/cpe_mapper.py ./

EXPOSE 9102

CMD ["python3", "main.py"]
