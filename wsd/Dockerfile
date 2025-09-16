FROM python:3.12-slim
# Labels für HA
LABEL \
    io.hass.name="WSD4HA" \
    io.hass.description="Registers at a document scanner as a WSD destination to receive and store any scanned documents in HA" \
    io.hass.version="0.0.9" \
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
COPY globals.py .
COPY main.py .
COPY config.py .
COPY scanner.py .
COPY wsd.py .
COPY webserver.py .
COPY templates.py .
#COPY translations/en.yaml ./translations

VOLUME ["/share/scans"]
EXPOSE 8110

CMD ["python3", "main.py"]
