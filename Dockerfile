# PromptWars Sentinel - Cloud Run image
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

WORKDIR /app

# Dependencies first so this layer stays cached (file is currently dependency-free)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Non-root runtime user
RUN useradd --system --no-create-home --shell /usr/sbin/nologin sentinel

COPY --chown=sentinel:sentinel core/ ./core/
COPY --chown=sentinel:sentinel static/ ./static/
COPY --chown=sentinel:sentinel server.py ./

USER sentinel
EXPOSE 8080

# Exec-form check: reads PORT inside Python (the old command used `os` without importing it)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT', '8080'), timeout=3)"]

CMD ["python", "server.py"]
