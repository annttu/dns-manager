import socket
from datetime import datetime
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from django.db import models
from django.db.models import Q
from django.contrib.auth.models import User, Group
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


def get_user_domain_filter(user):
    return Q(domain__users__pk=user.id) | Q(domain__groups__pk__in=[x.pk for x in user.groups.all()])


def get_user_filter(user):
    return Q(users__pk=user.id) | Q(groups__pk__in=[x.pk for x in user.groups.all()])


class Domain(models.Model):
    """
    Domain object
    """
    name = models.CharField(max_length=128, null=False, unique=True)
    comment = models.CharField(max_length=8192, null=False, default="")
    users = models.ManyToManyField(User)  # Users can do things to Domain
    groups = models.ManyToManyField(Group)  # Users on groups can do things to Domain
    tsig_key = models.CharField(max_length=8192, null=False, validators=[tsig_key_validator])
    tsig_type = models.CharField(max_length=8192, null=False, default="HMAC_MD5", choices=TSIG_KEY_TYPES)
    master = models.CharField(max_length=8192, null=False, help_text="DNS zone master server address", validators=[check_master])

    @classmethod
    def user_objects(cls, user):
        return cls.objects.filter(get_user_filter(user))

    @property
    def fqdn(self):
        return '%s.' % self.name.rstrip('.')

    def __str__(self):
        return 'Domain %s' % self.name


class Client(models.Model):
    """
    Client updates certain DNS record
    """
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
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

    @classmethod
    def user_objects(cls, user):
        return cls.objects.filter(get_user_domain_filter(user))

    def __str__(self):
        return 'Client %s' % self.fqdn


class DNSEntryCache(models.Model):
    """
    Cache for DNS-entries acquired from DNS-server using AXFR
    """

    class Meta:
        ordering = ['name', 'type']

    domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
    name = models.CharField(max_length=128, null=False, blank=True)
    ttl = models.IntegerField(null=False, default=360)
    record_class = models.CharField(max_length=128, null=False, default="IN", blank=False)
    type = models.CharField(max_length=128, null=False, blank=False)
    data = models.CharField(max_length=8192, null=False, blank=False)
    timestamp = models.DateTimeField(auto_now_add=True, auto_created=True, null=False)

    @property
    def fqdn(self):
        if self.name:
            return '%s.%s.' % (self.name, self.domain.name)
        else:
            return '%s.' % self.domain.name

    @property
    def age(self):
        if self.domain:
            print("asdf")
            delta = datetime.now() - self.timestamp
            print("delta: %s" % delta)
            return delta.seconds
        return None

    @classmethod
    def user_objects(cls, user):
        return cls.objects.filter(get_user_domain_filter(user))

    def __str__(self):
        return 'DNSEntryCache %s.%s %s %s' % (self.name, self.domain.name, self.type, self.data[:128])
