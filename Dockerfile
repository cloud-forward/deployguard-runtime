FROM python:3.11-slim

WORKDIR /app

# Python 버퍼링 비활성화
ENV PYTHONUNBUFFERED=1

# kubectl 설치
RUN apt-get update && apt-get install -y curl && \
    curl -LO "https://dl.k8s.io/release/v1.29.0/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && mv kubectl /usr/local/bin/kubectl && \
    apt-get clean

# 의존성 설치
COPY requirements.txt .
RUN pip install -r requirements.txt

# 코드 복사
COPY . .

CMD ["python3", "-u", "ingest/runner.py"]
