FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# kubectl 설치 (최신 stable 버전 자동 감지)
RUN apt-get update && apt-get install -y curl ca-certificates && \
    KUBECTL_VERSION=$(curl -L -s https://dl.k8s.io/release/stable.txt) && \
    curl -LO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && mv kubectl /usr/local/bin/kubectl && \
    apt-get purge -y curl && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 의존성
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 코드
COPY config        config/
COPY schemas       schemas/
COPY ingest        ingest/
COPY normalizer    normalizer/
COPY evidence_mapper evidence_mapper/

# non-root 유저로 실행
RUN useradd -u 1000 -m scanner
USER scanner

CMD ["python", "-u", "ingest/runner.py"]
