# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import manager.models
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('manager', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='DNSEntryCache',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, auto_created=True, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True, auto_created=True)),
                ('name', models.CharField(max_length=128)),
                ('ttl', models.IntegerField()),
                ('record_class', models.CharField(max_length=128)),
                ('type', models.CharField(max_length=128)),
                ('data', models.CharField(max_length=8192)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='dnsentrycache',
            name='domain',
            field=models.ForeignKey(to='manager.Domain', on_delete=models.CASCADE),
            preserve_default=True,
        ),
    ]
