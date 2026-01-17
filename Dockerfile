FROM python:3.13-slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends git make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

RUN git clone --depth 1 https://github.com/varunchopra/postkit.git \
    && cd postkit && make build

WORKDIR /app

COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir -r requirements.txt


# Postgres with postkit SQL schemas
FROM postgres:17 AS db
COPY --from=builder /build/postkit/dist/authn.sql /docker-entrypoint-initdb.d/01-authn.sql
COPY --from=builder /build/postkit/dist/authz.sql /docker-entrypoint-initdb.d/02-authz.sql
COPY --from=builder /build/postkit/dist/config.sql /docker-entrypoint-initdb.d/03-config.sql
COPY --from=builder /build/postkit/dist/meter.sql /docker-entrypoint-initdb.d/04-meter.sql
COPY init-app.sql /docker-entrypoint-initdb.d/05-app.sql


FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home appuser

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --chown=appuser:appuser app ./app

USER appuser

EXPOSE 5000

CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "4", "--access-logfile", "-", "app:create_app()"]
