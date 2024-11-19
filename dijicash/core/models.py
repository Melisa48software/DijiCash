# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.db import models
from django.utils import timezone
import datetime

# Modellerinizi buraya ekleyin

class transaction(models.Model):
    # Gönderenin genel anahtarı
    sender = models.CharField(max_length=5000, null=False)
    # Göndericinin cüzdanı
    senderwallet = models.CharField(max_length=5000, null=False)
    # Alıcının genel anahtarı
    receiver = models.CharField(max_length=5000, null=False)
    # Önceki blokun hash'i
    prevblockhash = models.CharField(max_length=5000, null=False)
    # Blokun hash'i
    blockhash = models.CharField(max_length=5000, null=False)
    # İşlem miktarı
    amount = models.IntegerField(null=False)
    # Tekil sayı (nonce)
    nonce = models.IntegerField(null=False)
    # İlk zaman damgası
    first_timestamp = models.IntegerField(null=False)
    # Kaydedilen zaman damgası (otomatik olarak eklenir)
    saved_timestamp = models.DateTimeField(auto_now_add=True)
    # P2PKH alanı
    P2PKH = models.CharField(max_length=5000, null=False)
    # Doğrulama alanı (isteğe bağlı)
    verification = models.BooleanField(blank=True)

    def __str__(self):
        return f"blockhash: {self.blockhash} sender: {self.sender}"
