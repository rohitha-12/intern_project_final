# Generated by Django 4.2.21 on 2025-05-27 02:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Myapp', '0015_vimeovideo_customuser_paid'),
    ]

    operations = [
        migrations.CreateModel(
            name='COIFormData',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('full_name', models.CharField(max_length=255)),
                ('phone_number', models.CharField(max_length=20)),
                ('website_name', models.CharField(blank=True, max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'db_table': 'coi_form_data',
            },
        ),
    ]
