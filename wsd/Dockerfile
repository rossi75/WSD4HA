FROM python:3.12-slim
# Labels für HA
LABEL \
    io.hass.name="WSD Scanner" \
    io.hass.description="Empfängt WSD/SSDP Scans und stellt sie im WebUI bereit" \
    io.hass.version="0.0.5" \
    io.hass.type="addon" \
    io.hass.arch="amd64|aarch64"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY run.py .
COPY config.yaml .

VOLUME ["/share/scans"]
EXPOSE 8110

#CMD ["python3", "run.py"]
CMD ["python3", "main.py"]
