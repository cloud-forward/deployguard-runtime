FROM python:3.11-slim

WORKDIR /app

# kubectl 설치
RUN apt-get update && apt-get install -y curl && \
    curl -LO "https://dl.k8s.io/release/v1.29.0/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && mv kubectl /usr/local/bin/kubectl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# 의존성
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 코드
COPY config config/
COPY schemas schemas/
COPY ingest ingest/

# 실행
CMD ["python", "-u", "ingest/runner.py"]