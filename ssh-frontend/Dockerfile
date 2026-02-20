FROM python:3.11-slim

WORKDIR /app

# Install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY ssh_server.py .

# Generate SSH host key
RUN ssh-keygen -t rsa -f ssh_host_key -N ''

# Expose SSH port
EXPOSE 2222

# Run server
CMD ["python", "ssh_server.py"]
