FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend backend
COPY frontend frontend
COPY policies policies
COPY results results
RUN useradd --uid 10001 agentsnap && mkdir -p /data && chown agentsnap /data
USER agentsnap
ENV AGENTSNAP_DATA=/data
EXPOSE 8740
HEALTHCHECK --interval=15s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8740/healthz')"
# Secrets come from the environment: AGENTSNAP_API_KEYS, AGENTSNAP_SIGNING_KEY (path to a mounted PEM)
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8740"]
