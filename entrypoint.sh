#!/bin/sh

cd /app/DNSManager
# Run migrations
./manage.py migrate

# Run server
export HOME=/app
exec gunicorn manager.wsgi:application --workers 4 --bind 0.0.0.0:8080
