# Generated by Django 3.1.2 on 2020-10-02 02:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("drf_user", "0006_auto_20181220_1911"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="profile_image",
            field=models.ImageField(
                blank=True,
                null=True,
                upload_to="user_images",
                verbose_name="Profile Photo",
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="email",
            field=models.EmailField(
                max_length=254, unique=True, verbose_name="Email Address"
            ),
        ),
    ]
