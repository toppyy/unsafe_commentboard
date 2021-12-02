# Generated by Django 3.2.9 on 2021-12-01 19:20

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('src', '0004_alter_comment_pub_date'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.TextField()),
                ('password', models.TextField()),
            ],
        ),
        migrations.AlterField(
            model_name='comment',
            name='by',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='src.user'),
        ),
    ]
