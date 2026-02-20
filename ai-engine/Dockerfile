FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    python -m spacy download en_core_web_sm

# Copy source code
COPY src/ ./

# Create directories
RUN mkdir -p /models /cache

RUN useradd -m -u 1000 aiuser && \
    chown -R aiuser:aiuser /app /models /cache

USER aiuser

# Set environment for transformers cache
ENV TRANSFORMERS_CACHE=/cache
ENV HF_HOME=/cache

EXPOSE 8002

CMD ["python", "main.py"]
