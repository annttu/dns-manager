DNSManager
==========

DNSManager uses TSIG-key to add, update and delete DNS-records. DNSmanager works with all DNS-servers which support Dynamic updates [(RFC2136)](http://tools.ietf.org/html/rfc2136) using secure transport [(RFC3007)](http://tools.ietf.org/html/rfc3007). For example Bind9 and PowerDNS are supported.


Installation
============

Install packages etc.

    virtualenv env --python=python3.4
    . env/bin/activate
    pip install -r requirements.txt
    cd DNSManager
    vi manager/settings.py
    ./manage.py syncdb
    


Usage
=====

    ./manage.py runserver

Zone config for Bind9
=====================

Configuration for bind9 to allow dynamic updates using TSIG-key.

Create first TSIG-key.

    dnssec-keygen -a HMAC-SHA256 -b 256 -n HOST domain.tld.tsigkey
    cat domain.tld.tsigkey.*.key

Copy the bas64 encoded key and use to replace secret in <b>key</b> row below. Full row is also needed later when domain is added to the frontend.

Update zone config with following

    key "domain.tld.tsigkey." { algorithm hmac-sha256; secret "XC+/XU45WGC6ycCT9uORuqs+cPWqoyMl98F63Cw2czo="; };
    zone "domain.tld" { type master; file "/etc/bind/domain.tld"; allow-transfer { my-master-server-here; key "domain.tld.tsigkey."; }; allow-update { key "domain.tld.tsigkey."; }; };

Note to use exactly same name for key in config than in dnssec-keygen command. Otherwise it does not work.

Finally reload config

    rndc reload

License
=======

The MIT License (MIT)

Copyright (c) 2015 Antti Jaakkola

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