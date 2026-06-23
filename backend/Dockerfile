FROM python:3.11-slim-bookworm

RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get update --fix-missing && \
    apt-get install -y --no-install-recommends \
        libmagic1 \
        file \
        wget \
        unzip \
        default-jre-headless && \
    rm -rf /var/lib/apt/lists/*

# Install jadx
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip \
    -O /tmp/jadx.zip && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    rm /tmp/jadx.zip && \
    chmod +x /opt/jadx/bin/jadx
ENV PATH="/opt/jadx/bin:$PATH"

# Install apktool
RUN wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool \
    -O /usr/local/bin/apktool && \
    wget -q https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar \
    -O /usr/local/bin/apktool.jar && \
    chmod +x /usr/local/bin/apktool

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create a dedicated non-root user and chown all writable paths. The container
# runs as this UID in production so a compromised analyzer can't write outside
# the scan/upload/report roots or the SQLite data dir.
RUN groupadd --system --gid 1001 cortex \
 && useradd  --system --uid 1001 --gid cortex --create-home --shell /usr/sbin/nologin cortex \
 && mkdir -p /tmp/cortex/uploads /tmp/cortex/reports /tmp/cortex/scans /data \
 && chown -R cortex:cortex /app /tmp/cortex /data

ENV CORTEX_DATA_DIR=/data
ENV JADX_PATH=/opt/jadx/bin/jadx
ENV APKTOOL_PATH=/usr/local/bin/apktool

USER cortex

EXPOSE 8000

# Container-level healthcheck so orchestrators (docker-compose, k8s) can
# recognise a wedged backend without hitting the LB.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8000/api/health >/dev/null 2>&1 || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
