FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY run.py .
COPY config.yaml .

VOLUME ["/share/scans"]
EXPOSE 8080

CMD ["python3", "run.py"]
