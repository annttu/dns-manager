# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import manager.models
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Client',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, auto_created=True, verbose_name='ID')),
                ('secret', models.CharField(max_length=1024)),
                ('name', models.CharField(max_length=128)),
                ('comment', models.CharField(default='', max_length=8192)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Domain',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, auto_created=True, verbose_name='ID')),
                ('name', models.CharField(unique=True, max_length=128)),
                ('comment', models.CharField(default='', max_length=8192)),
                ('tsig_key', models.CharField(validators=[manager.models.tsig_key_validator], max_length=8192)),
                ('tsig_type', models.CharField(default='HMAC_MD5', choices=[('HMAC_MD5', 'HMAC-MD5'), ('HMAC_SHA1', 'HMAC-SHA1'), ('HMAC_SHA224', 'HMAC-SHA224'), ('HMAC_SHA256', 'HMAC-SHA256'), ('HMAC_SHA384', 'HMAC-SHA384'), ('HMAC_SHA512', 'HMAC-SHA512')], max_length=8192)),
                ('master', models.CharField(validators=[manager.models.check_master], help_text='DNS zone master server address', max_length=8192)),
                ('users', models.ManyToManyField(to=settings.AUTH_USER_MODEL)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='client',
            name='domain',
            field=models.ForeignKey(to='manager.Domain'),
            preserve_default=True,
        ),
        migrations.AlterUniqueTogether(
            name='client',
            unique_together=set([('domain', 'name')]),
        ),
    ]
