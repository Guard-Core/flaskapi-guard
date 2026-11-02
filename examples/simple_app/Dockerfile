FROM python:3.10-slim

RUN useradd --create-home --uid 10001 app \
    && mkdir /app \
    && chown app:app /app

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

USER 10001

COPY --chown=app:app . /app/

EXPOSE 8000

# Probes port 8000. Any HTTP answer counts as alive; a refused connection or a timeout fails.
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request, urllib.error\ntry:\n    urllib.request.urlopen('http://127.0.0.1:8000/', timeout=3)\nexcept urllib.error.HTTPError:\n    pass"]

CMD ["gunicorn", "main:app", "--bind", "0.0.0.0:8000", "--reload"]
