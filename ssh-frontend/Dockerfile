FROM python:3.11-slim

# Install openssh for key generation
RUN apt-get update && \
    apt-get install -y openssh-client && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY src/ssh_server.py .

# Generate SSH host key
RUN ssh-keygen -t rsa -f ssh_host_key -N ''

# Expose SSH port
EXPOSE 2222

# Run server
CMD ["python", "ssh_server.py"]
