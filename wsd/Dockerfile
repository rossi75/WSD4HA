FROM python:3.12-slim
# Labels für HA
LABEL \
    io.hass.name="WSD4HA" \
    io.hass.description="Registers at a document scanner as a WSD destination to receive and store any scanned documents in HA" \
    io.hass.version="0.1.1" \
    io.hass.type="addon" \
    io.hass.arch="amd64|aarch64"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

#COPY config.yaml /app/
#COPY main.py /app/
#COPY config.py /app/
#COPY scanner.py /app/
#COPY wsd.py /app/
#COPY webserver.py /app/

COPY config.yaml .
COPY config.py .
COPY globals.py .
COPY main.py .
COPY parse.py .
COPY scan_job.py .
COPY scanner.py .
COPY send.py .
COPY server.py .
COPY templates.py .
COPY translations/en.yaml ./translations
#COPY webserver.py .
COPY wsd.py .

EXPOSE 8110
EXPOSE 5357
VOLUME ["/share/scans"]

CMD ["python3", "main.py"]
