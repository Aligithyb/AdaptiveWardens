FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./

RUN useradd -m -u 1000 httpuser && \
    chown -R httpuser:httpuser /app

USER httpuser

EXPOSE 8080

CMD ["python", "http_server.py"]
