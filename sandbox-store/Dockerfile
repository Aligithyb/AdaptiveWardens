FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./
COPY schemas/ ./schemas/

RUN mkdir -p /data

RUN useradd -m -u 1000 sandbox && chown -R sandbox:sandbox /app /data
USER sandbox

EXPOSE 8001

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8001"]
