FROM python:3.12-slim
# Labels für HA
LABEL \
    io.hass.name="WSD Scanner" \
    io.hass.description="Empfängt WSD Scans und stellt sie im WebUI bereit" \
    io.hass.version="0.0.4" \
    io.hass.type="addon" \
    io.hass.arch="amd64|aarch64"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

#COPY run.py .

#COPY config.yaml /app/
#COPY main.py /app/
#COPY config.py /app/
#COPY scanner.py /app/
#COPY wsd.py /app/
#COPY webserver.py /app/

COPY config.yaml .
#COPY state.py .
COPY globals.py .
COPY main.py .
COPY config.py .
COPY scanner.py .
COPY wsd.py .
COPY webserver.py .

VOLUME ["/share/scans"]
EXPOSE 8110

#CMD ["python3", "run.py"]
CMD ["python3", "main.py"]
