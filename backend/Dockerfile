FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --timeout=180 --retries=5 -r requirements.txt
RUN addgroup --system --gid 10001 sentinel \
    && adduser --system --uid 10001 --ingroup sentinel sentinel \
    && mkdir -p /app/.data \
    && chown -R sentinel:sentinel /app
COPY --chown=sentinel:sentinel app ./app
COPY --chown=sentinel:sentinel alembic ./alembic
COPY --chown=sentinel:sentinel alembic.ini ./alembic.ini
COPY --chown=sentinel:sentinel pyproject.toml ./pyproject.toml
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
