FROM docker.io/python:3.14-alpine AS dnsmanager

RUN mkdir /app

RUN apk add build-base libpq libpq-dev

COPY requirements.txt /app/requirements.txt

RUN pip3 install --no-cache-dir -r /app/requirements.txt

COPY DNSManager /app/DNSManager
COPY entrypoint.sh /app/entrypoint.sh
RUN mkdir /app/DNSManager/staticfiles/ /app/.gunicorn
RUN chown nobody: /app/.gunicorn

WORKDIR /app/DNSManager
ENV PYTHONPATH=/app

RUN ./manage.py collectstatic

USER nobody

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
