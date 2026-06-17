FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ssh_server.py .

# Host key is NOT generated at build time. It's generated at runtime into
# /data (a persistent volume) so the fingerprint is stable across container
# restarts — production servers don't rotate host keys on every reboot.

# Neutralize the Docker container marker file. Real production servers
# don't have /.dockerenv — leave it as a zero-byte file with no permissions
# so `cat /.dockerenv` returns empty rather than "No such file or directory"
# (which is itself a tell if an attacker expects to find it).
RUN rm -f /.dockerenv && touch /.dockerenv && chmod 000 /.dockerenv

EXPOSE 2222

CMD ["python", "ssh_server.py"]
