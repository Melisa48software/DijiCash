# Django 4.2.9 tarafından 2024-01-27 14:58 tarihinde oluşturuldu

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        # 'transaction' adında bir model oluşturuyoruz
        migrations.CreateModel(
            name='transaction',
            fields=[
                # 'id' adında birincil anahtar alanı oluşturuyoruz
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                # 'sender' adında gönderici alanı, maksimum uzunluk 5000 karakter
                ('sender', models.CharField(max_length=5000)),
                # 'senderwallet' adında gönderici cüzdan alanı, maksimum uzunluk 5000 karakter
                ('senderwallet', models.CharField(max_length=5000)),
                # 'receiver' adında alıcı alanı, maksimum uzunluk 5000 karakter
                ('receiver', models.CharField(max_length=5000)),
                # 'prevblockhash' adında önceki blok hash alanı, maksimum uzunluk 5000 karakter
                ('prevblockhash', models.CharField(max_length=5000)),
                # 'blockhash' adında blok hash alanı, maksimum uzunluk 5000 karakter
                ('blockhash', models.CharField(max_length=5000)),
                # 'amount' adında miktar alanı, tamsayı değeri
                ('amount', models.IntegerField()),
                # 'nonce' adında nonce alanı, tamsayı değeri
                ('nonce', models.IntegerField()),
                # 'first_timestamp' adında ilk zaman damgası alanı, tamsayı değeri
                ('first_timestamp', models.IntegerField()),
                # 'saved_timestamp' adında kaydedilen zaman damgası alanı, otomatik olarak şu anki tarihi ekler
                ('saved_timestamp', models.DateTimeField(auto_now_add=True)),
                # 'P2PKH' adında P2PKH alanı, maksimum uzunluk 5000 karakter
                ('P2PKH', models.CharField(max_length=5000)),
                # 'verification' adında doğrulama alanı, boş bırakılabilir boolean değeri
                ('verification', models.BooleanField(blank=True)),
            ],
        ),
    ]
