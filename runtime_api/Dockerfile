FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

COPY runtime_api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY runtime_api/ runtime_api/

RUN useradd -u 1000 -m apiuser
USER apiuser

EXPOSE 8080

CMD ["uvicorn", "runtime_api.main:app", "--host", "0.0.0.0", "--port", "8080"]
