FROM python:3.12-slim-bookworm

ARG TECTONIC_VERSION=0.15.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    tar \
    libgraphite2-3 \
    libharfbuzz0b \
    libfreetype6 \
    fontconfig \
    && curl -fsSL "https://github.com/tectonic-typesetting/tectonic/releases/download/tectonic%40${TECTONIC_VERSION}/tectonic-${TECTONIC_VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
       | tar -xz -C /usr/local/bin tectonic \
    && tectonic --version \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data/alerts

CMD ["python", "-m", "cert_watcher", "--config", "config/assets.example.yaml"]