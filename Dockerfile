# ── Stage 1: install dependencies ──────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .

# Install into /build/pkgs so we can copy just the packages (no pip) to runtime
RUN pip install --no-cache-dir --target=/build/pkgs -r requirements.txt

# ── Stage 2: minimal runtime image ─────────────────────────────────────────
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/pkgs \
    FLASK_APP=app.main:app \
    ADMIN_USER=admin \
    ADMIN_PASS=changeme

WORKDIR /app

# Copy only the installed packages (no pip/setuptools in runtime layer)
COPY --from=builder /build/pkgs ./pkgs

# Copy application source
COPY app/ ./app/

EXPOSE 5000

# gunicorn lives inside pkgs; run it via python -m
CMD ["python", "-m", "gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "1", \
     "--timeout", "60", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app.main:app"]
