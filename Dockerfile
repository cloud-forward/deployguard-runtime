FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# kubectl 설치
RUN apt-get update && apt-get install -y curl ca-certificates && \
    KUBECTL_VERSION=$(curl -L -s https://dl.k8s.io/release/stable.txt) && \
    curl -LO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && mv kubectl /usr/local/bin/kubectl && \
    apt-get purge -y curl && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY runner.py .
COPY config/ config/
COPY schemas/ schemas/
COPY normalizer/ normalizer/
COPY fact_builder/ fact_builder/
COPY forwarder/ forwarder/
COPY registry/ registry/
COPY suppression/ suppression/
COPY policies/ policies/

RUN useradd -u 1000 -m scanner
USER scanner

CMD ["python", "-u", "runner.py"]