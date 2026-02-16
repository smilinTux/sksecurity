# SKSecurity Enterprise - Official Docker Image
FROM python:3.11-slim

# Metadata
LABEL maintainer="team@smilintux.org"
LABEL description="Enterprise-grade security for AI agent ecosystems"
LABEL version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/smilinTux/SKSecurity"
LABEL org.opencontainers.image.documentation="https://docs.sksecurity.com"
LABEL org.opencontainers.image.vendor="smilinTux"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Create app directory and user
RUN useradd --create-home --shell /bin/bash sksecurity
WORKDIR /home/sksecurity

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install SKSecurity
RUN pip install --no-cache-dir .

# Create necessary directories
RUN mkdir -p /home/sksecurity/.config/sksecurity \
    /home/sksecurity/.sksecurity/logs \
    /home/sksecurity/.sksecurity/quarantine \
    && chown -R sksecurity:sksecurity /home/sksecurity

# Switch to non-root user
USER sksecurity

# Create default configuration
RUN sksecurity init --config-only

# Expose dashboard port
EXPOSE 8888

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8888/api/status || exit 1

# Default command
CMD ["sksecurity", "dashboard", "--host", "0.0.0.0", "--port", "8888"]