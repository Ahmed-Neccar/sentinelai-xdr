# SentinelAI network sensor for Linux (passive flow headers only).
#
#   docker build -f sensor/linux/Dockerfile -t sentinelai-sensor sensor
#   docker run -d --name sentinel-sensor --restart unless-stopped --network host \
#     --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN \
#     -v sentinel-sensor-state:/app/runtime \
#     -v /etc/sentinel/sensor-credentials.json:/etc/sentinel/sensor-credentials.json:ro \
#     -e SENTINEL_SERVER=https://sentinel.example.com -e SENTINEL_INTERFACE=eth0 \
#     sentinelai-sensor
#
# The state volume keeps the sensor's identity and signing key; without it every restart looks
# like a new, unregistered sensor and the server refuses it.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.lock ./requirements.lock
RUN pip install -r requirements.lock
COPY live_sensor.py response_actions.py windows_security.py ./
RUN mkdir -p /app/runtime

# Capturing packets needs the raw-socket capability, so this container runs as root inside its
# own namespace with every other capability dropped by the run command above.
CMD ["sh", "-c", "exec python live_sensor.py --server \"$SENTINEL_SERVER\" --interface \"$SENTINEL_INTERFACE\" --duration-seconds 0 --credentials-file /etc/sentinel/sensor-credentials.json --source-name \"${SENTINEL_SOURCE_NAME:-$(hostname)-linux-sensor}\""]
