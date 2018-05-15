# -*- coding: utf-8 -*-
# Generated by Django 1.11.9 on 2018-03-26 15:45
from __future__ import unicode_literals

import django_extensions.db.fields
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('referrals', '0004_auto_20170215_2234'),
    ]

    operations = [
        migrations.AlterField(
            model_name='referral',
            name='created',
            field=django_extensions.db.fields.CreationDateTimeField(auto_now_add=True, verbose_name='created'),
        ),
        migrations.AlterField(
            model_name='referral',
            name='modified',
            field=django_extensions.db.fields.ModificationDateTimeField(auto_now=True, verbose_name='modified'),
        ),
    ]
