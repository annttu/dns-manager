#!/bin/sh

cd /app/DNSManager
# Run migrations
./manage.py migrate

# Run server
exec ./manage.py runserver 0.0.0.0:8080
