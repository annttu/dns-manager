FROM python:3.7.3-alpine3.9

ENV PYTHONUNBUFFERED 1
WORKDIR /dns-manager
COPY ./DNSManager /dns-manager
COPY requirements.txt /tmp

RUN apk add --no-cache postgresql-dev musl-dev gcc && \
    pip install --upgrade pip && \
    pip install -r /tmp/requirements.txt

