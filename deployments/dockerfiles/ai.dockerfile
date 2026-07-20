FROM python:3.13-slim

WORKDIR /app

COPY services/ai/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt --no-cache-dir

COPY services/ai/main.py ./
COPY services/utils.py ./
COPY services/logger.py ./
COPY services/health.py ./

EXPOSE 9104

CMD ["python3", "main.py"]
