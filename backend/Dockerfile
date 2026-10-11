# UEBA Platform - Python 3.12-slim, non-root user
FROM python:3.12-slim

# Create non-root user
RUN groupadd -r ueba && useradd -r -g ueba -d /app -s /bin/bash ueba

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY ueba/ ./ueba/
COPY config.yaml .

# Create data directory with correct permissions
RUN mkdir -p /app/data/geoip /app/data/model_cache && chown -R ueba:ueba /app

# Switch to non-root user
USER ueba

# Environment defaults (overridable at runtime)
ENV UEBA_DB_PATH=/app/data/ueba.db
ENV UEBA_DATA_DIR=/app/data
ENV API_HOST=0.0.0.0
ENV API_PORT=28819
ENV SYSLOG_PORT=1514
ENV LOG_LEVEL=INFO

EXPOSE 28819 1514/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:28819/api/health || exit 1

ENTRYPOINT ["python", "-m", "ueba"]
