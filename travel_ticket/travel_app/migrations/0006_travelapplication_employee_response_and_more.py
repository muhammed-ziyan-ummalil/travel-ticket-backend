# Generated by Django 4.2 on 2025-03-20 04:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('travel_app', '0005_travelapplication_purpose'),
    ]

    operations = [
        migrations.AddField(
            model_name='travelapplication',
            name='employee_response',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='travelapplication',
            name='info_requested_date',
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='travelapplication',
            name='requested_for_info',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='travelapplication',
            name='response_date',
            field=models.DateField(blank=True, null=True),
        ),
    ]
