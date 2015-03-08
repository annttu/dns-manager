import socket
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from django.db import models
from django.contrib.auth.models import User
from dnsutils import checkKey, DynDNSException

from hashlib import sha512
import string
from random import choice

RECORD_TYPES = (
    ('A', 'IPv4 record'),
    ('AAAA', 'IPv6 record'),
    ('PTR', 'reverse record'),
    ('MX', 'MX record'),
)

TSIG_KEY_TYPES = (
    ('HMAC_MD5','HMAC-MD5'),
    ('HMAC_SHA1','HMAC-SHA1'),
    ('HMAC_SHA224','HMAC-SHA224'),
    ('HMAC_SHA256','HMAC-SHA256'),
    ('HMAC_SHA384','HMAC-SHA384'),
    ('HMAC_SHA512','HMAC-SHA512'),
)


def tsig_key_validator(value):
    try:
        checkKey(value)
    except DynDNSException:
        raise ValidationError("Invalid TSIG_KEY")


def check_master(value):
    try:
        socket.gethostbyname(value)
    except socket.gaierror:
        raise ValueError("%s is not valid dns-server" % value)


class Domain(models.Model):
    """
    Domain object
    """
    name = models.CharField(max_length=128, null=False, unique=True)
    comment = models.CharField(max_length=8192, null=False, default="")
    users = models.ManyToManyField(User)  # Users can do thins to Domain
    tsig_key = models.CharField(max_length=8192, null=False, validators=[tsig_key_validator])
    tsig_type = models.CharField(max_length=8192, null=False, default="HMAC_MD5", choices=TSIG_KEY_TYPES)
    master = models.CharField(max_length=8192, null=False, help_text="DNS zone master server address", validators=[check_master])


    @property
    def fqdn(self):
        return '%s.' % self.name.rstrip('.')

    def __str__(self):
        return 'Domain %s' % self.name


class Client(models.Model):
    """
    Client updates certain DNS record
    """
    domain = models.ForeignKey(Domain)
    secret = models.CharField(max_length=1024, null=False)  # SHA512 hashed secret
    name = models.CharField(max_length=128, null=False)
    comment = models.CharField(max_length=8192, null=False, default="")

    class Meta:
        unique_together = ('domain', 'name',)

    @property
    def fqdn(self):
        return '%s.%s.' % (self.name, self.domain.name)

    def save(self, *args, **kwargs):
        # Hash secret if not hashed
        if not self.secret.startswith('$1$'):
            self.secret = '$1$' + sha512(self.secret.encode("utf-8")).hexdigest()
        super(Client, self).save(*args, **kwargs)


    def __str__(self):
        return 'Client %s' % self.fqdn