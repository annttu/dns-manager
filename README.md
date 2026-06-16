DNSManager
==========

Web DNS record manager with DynDNS support.

DNSManager uses TSIG-key to add, update and delete DNS-records. DNSManager works with all DNS-servers that 
support Dynamic updates [(RFC2136)](http://tools.ietf.org/html/rfc2136) using secure transport [(RFC3007)](http://tools.ietf.org/html/rfc3007).
For example Bind9 and PowerDNS are supported.


Container installation
=======

Copy [docker-compose.yaml](https://github.com/annttu/dns-manager/blob/master/docker-compose.yaml) file. Edit passwords and ports if needed.

Start containers

```
docker compose up
```

Create superuser

```
docker exec --it dns-manager-app ./manage.py createsuperuser
```

Installation locally
============

Prerequisites

 * Running postgresql server
 * Some packages
   * sudo apt-get install libpq-dev python3-dev ( debian, ubuntu, etc. )
   * sudo yum install postgresql-devel ( centos, redhat, etc. )

Install packages etc.

```
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
cd DNSManager
cp local_settings.py.sample local_settings.py
vim local_settings.py
./manage.py migrate
./manage.py collectstatic
```

Setup superuser

```
./manage.py createsuperuser
```

Start server with manage.py runserver or gunicorn

```
./manage.py runserver 8080
```

or

```
gunicorn gunicorn manager.wsgi:application --workers 4 --bind :8080
```

Connecting
===

Go to http://127.0.0.1:8080

I strongly recommend to configure a reverse proxy with an SSL-support for
connections over Internet. Nginx or Apache is fine for this.


Zone config for Bind9
=====================

Configuration for bind9 to allow dynamic updates using TSIG-key.

Create first TSIG-key.

    dnssec-keygen -a HMAC-SHA256 -b 256 -n HOST domain.tld.tsigkey
    cat domain.tld.tsigkey.*.key

Copy the base64 encoded key and use it to replace the secret in <b>key</b> row below. The Full row is also needed later when a domain is added to the frontend.

Update zone config with the following configuration

    key "domain.tld.tsigkey." { algorithm hmac-sha256; secret "XC+/XU45WGC6ycCT9uORuqs+cPWqoyMl98F63Cw2czo="; };
    zone "domain.tld" { type master; file "/etc/bind/domain.tld"; allow-transfer { my-master-server-here; key "domain.tld.tsigkey."; }; allow-update { key "domain.tld.tsigkey."; }; };

Note to use exactly same name for the key in config than in dnssec-keygen command. Otherwise it does not work.

Finally, reload config

    rndc reload

License
=======

The MIT License (MIT)

Copyright (c) 2015-2026 Antti Jaakkola

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
