FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ssh_server.py .

# Host key is NOT generated at build time. It's generated at runtime into
# /data (a persistent volume) so the fingerprint is stable across container
# restarts — production servers don't rotate host keys on every reboot.

EXPOSE 2222

CMD ["python", "ssh_server.py"]
