FROM python:3.11-slim

# Run as a non-root user. The honeypot binds high ports by default in the
# container; map them to real ports at the host with -p.
RUN useradd --create-home --uid 10001 honey
WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY honeypot ./honeypot

USER honey
ENV PYTHONUNBUFFERED=1

EXPOSE 8080 2222 2323 8888
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"

ENTRYPOINT ["python", "-m", "honeypot"]
CMD ["--ports", "2222,2323,8888", "--dashboard-port", "8080", "--db", "/app/data/honeypot.db"]
