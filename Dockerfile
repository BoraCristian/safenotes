FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SAFENOTES_ENV=production
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn==23.0.0

COPY safenotes ./safenotes

RUN useradd --create-home --uid 10001 safenotes && mkdir -p /app/instance && chown safenotes /app/instance
USER safenotes
VOLUME ["/app/instance"]

EXPOSE 8000
# SAFENOTES_SECRET_KEY must be provided at runtime; run behind an HTTPS reverse proxy
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "safenotes:create_app()"]
