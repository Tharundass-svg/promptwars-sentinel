# PromptWars Sentinel - Production Cloud Run Dockerfile
FROM python:3.11-slim

# Security: Set working directory and non-root execution
WORKDIR /app

# Copy application files
COPY core/ /app/core/
COPY static/ /app/static/
COPY server.py /app/server.py
COPY requirements.txt /app/requirements.txt

# Create non-root user
RUN adduser --disabled-password --gecos "" sentineluser && \
    chown -R sentineluser:sentineluser /app

USER sentineluser

# Google Cloud Run default port
ENV PORT=8080
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:' + str(os.environ.get('PORT', 8080)) + '/health')" || exit 1

# Launch production server
CMD ["python", "server.py"]
