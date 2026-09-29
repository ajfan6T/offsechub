# ---- build the React frontend ---------------------------------------------
FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- runtime: FastAPI serves the API and the built SPA ----------------------
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OFFSECHUB_DATABASE_URL=sqlite:////data/offsechub.db \
    OFFSECHUB_STORAGE_DIR=/data/evidence
RUN useradd --create-home --uid 10001 offsechub && mkdir /data && chown offsechub /data
WORKDIR /app
COPY backend/ ./backend/
COPY samples/ ./samples/
RUN pip install --no-cache-dir -e "./backend[postgres]"
COPY --from=web /web/dist ./frontend/dist
USER offsechub
WORKDIR /app/backend
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')"
# --proxy-headers so audit logs record the real client IP behind a TLS proxy.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
