FROM python:3.13-slim

WORKDIR /app

COPY services/intelligence/requirements-correlator.txt ./requirements.txt
RUN pip install -r requirements.txt --no-cache-dir

COPY services/intelligence/correlator.py ./main.py
COPY services/utils.py ./
COPY services/logger.py ./
COPY services/health.py ./

EXPOSE 9103

CMD ["python3", "main.py"]
