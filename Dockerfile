ARG PYTHON_IMAGE=python:3.12-slim

FROM ${PYTHON_IMAGE} AS builder

ARG PRODUCT_EDITION=community
ARG BUILD_REVISION=unknown
ARG ARMORPILOT_LICENSE_PUBLIC_KEY_B64=""

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-build.txt ./
RUN pip install --no-cache-dir --target=/build/pkgs -r requirements.txt \
    && pip install --no-cache-dir -r requirements-build.txt

COPY app/ /build/source/app/
COPY tools/prepare_runtime.py tools/build_extensions.py /build/tools/

RUN python /build/tools/prepare_runtime.py \
        --source /build/source/app \
        --output /build/runtime/app \
        --edition "${PRODUCT_EDITION}" \
        --revision "${BUILD_REVISION}" \
        --license-public-key "${ARMORPILOT_LICENSE_PUBLIC_KEY_B64}" \
    && python /build/tools/build_extensions.py --root /build/runtime \
    && test -z "$(find /build/runtime/app -type f -name '*.py' -print -quit)"

FROM ${PYTHON_IMAGE} AS runtime

ARG PRODUCT_EDITION=community
ARG BUILD_REVISION=unknown

LABEL org.opencontainers.image.title="ArmorPilot" \
      org.opencontainers.image.description="Kubernetes runtime security management platform powered by vArmor" \
      org.opencontainers.image.source="https://github.com/Kaint2051/armor-pilot" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.armorpilot.edition="${PRODUCT_EDITION}" \
      org.opencontainers.image.revision="${BUILD_REVISION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/pkgs \
    FLASK_APP=app.main:app \
    HOME=/tmp

WORKDIR /app

RUN groupadd --gid 10001 armorpilot \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin armorpilot \
    && mkdir -p /app/data \
    && chown -R 10001:10001 /app/data

COPY --from=builder /build/pkgs ./pkgs
COPY --from=builder /build/runtime/app ./app

USER 10001:10001

EXPOSE 5000

CMD ["python", "-m", "gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "1", \
     "--timeout", "60", \
     "--worker-tmp-dir", "/tmp", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app.main:app"]
