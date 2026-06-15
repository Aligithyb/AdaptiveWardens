FROM python:3.11-slim

WORKDIR /app

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY schemas/ ./schemas/

# Create data directory and set ownership for the app user
RUN mkdir -p /data && chown -R 1001:1001 /data /app

# Expose port
EXPOSE 8001

# Create non-root user
RUN addgroup --system --gid 1001 app && adduser --system --uid 1001 --ingroup app app
USER app

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8001/health')" || exit 1

# Run API server
CMD ["python", "src/api.py"]
