# Generated by Django 3.2b1 on 2021-03-07 02:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rooms', '0002_auto_20191216_0937'),
    ]

    operations = [
        migrations.AlterField(
            model_name='photo',
            name='id',
            field=models.BigAutoField(primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='room',
            name='id',
            field=models.BigAutoField(primary_key=True, serialize=False),
        ),
    ]