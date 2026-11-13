# Token Federation Proxy — backend container.
#
# The proxy is Python-stdlib only (no pip deps), so this is a tiny image.
# It speaks plain HTTP on TFP_PORT; TLS is terminated by Caddy in front
# (see docker/Caddyfile + docker/docker-compose.yml). Runs as non-root.

FROM python:3.13-slim

# Unbuffered stdout so logs appear promptly when captured by Docker.
ENV PYTHONUNBUFFERED=1 \
    TFP_PORT=9090

# Dedicated unprivileged runtime user.
RUN groupadd --system tfp \
 && useradd  --system --gid tfp --no-create-home --home-dir /app tfp

WORKDIR /app
COPY proxy/proxy.py /app/proxy.py

USER tfp
EXPOSE 9090

# Liveness: hit the in-proxy /healthz route (answered locally, no auth, no
# token exchange). Uses TFP_PORT from the container env so it tracks config.
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD python3 -c "import os,urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ['TFP_PORT']+'/healthz', timeout=2).status==200 else 1)"

CMD ["python3", "proxy.py"]
