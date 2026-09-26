FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py wsgi.py manage.py ./
RUN useradd --uid 10001 --create-home taskgate && mkdir -p /var/data && chown taskgate:taskgate /var/data
USER taskgate
EXPOSE 8787
CMD ["gunicorn", "--bind", "0.0.0.0:8787", "--workers", "1", "--threads", "8", "--timeout", "30", "wsgi:application()"]
