FROM docker.io/python:3.13-alpine AS dnsmanager

RUN mkdir /app

RUN apk add build-base libpq libpq-dev

COPY requirements.txt /app/requirements.txt

RUN pip3 install --no-cache-dir -r /app/requirements.txt

COPY DNSManager /app/DNSManager
COPY entrypoint.sh /app/entrypoint.sh

USER nobody

ENTRYPOINT ["/app/entrypoint.sh"]
