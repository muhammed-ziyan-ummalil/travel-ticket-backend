# Generated by Django 4.2 on 2025-03-06 17:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('travel_app', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='leaverequest',
            name='status',
            field=models.CharField(choices=[('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected'), ('in_progress', 'In Progress'), ('closed', 'Closed'), ('needs_editing', 'Needs Editing'), ('requested_for_info', 'Requested for Info'), ('resubmitted', 'Resubmitted'), ('reconsideration', 'Reconsideration'), ('cancelled', 'Cancelled')], default='pending', max_length=20),
        ),
    ]
