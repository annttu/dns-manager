# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0001_initial'),
        ('manager', '0002_dns_cache'),
    ]

    operations = [
        migrations.AddField(
            model_name='domain',
            name='groups',
            field=models.ManyToManyField(to='auth.Group'),
            preserve_default=True,
        )
    ]
