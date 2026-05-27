# ── Build Stage ──────────────────────────────────────────
FROM python:3.11-alpine3.19 AS builder
 
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    mariadb-dev \
    mariadb-connector-c-dev
 
WORKDIR /app
COPY Backend/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt
 
# ── Runtime Stage ─────────────────────────────────────────
FROM python:3.11-alpine3.19
 
RUN apk add --no-cache \
    libstdc++ \
    mariadb-connector-c \
&& adduser -D appuser
 
WORKDIR /app
COPY --from=builder --chown=appuser:appuser /install /usr/local
COPY --chown=appuser:appuser Backend/ Backend/
 
USER appuser
EXPOSE 8000
 
CMD ["uvicorn", "Backend.main:app", "--host", "0.0.0.0", "--port", "8000"]