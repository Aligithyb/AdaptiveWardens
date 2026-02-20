FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY src/ ./

# Create directories
RUN mkdir -p /configs /logs

# Create non-root user
RUN useradd -m -u 1000 sshuser && \
    chown -R sshuser:sshuser /app /configs /logs

USER sshuser

EXPOSE 2222

CMD ["python", "ssh_server.py"]
