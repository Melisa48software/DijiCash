# -*- coding: utf-8 -*-
import uuid, json, string, random, urllib, base64, os, sys, time, pickle, collections, math, arrow, hashlib, websocket, bson
from ecdsa import SigningKey, SECP256k1, NIST384p, BadSignatureError, VerifyingKey
from django.conf import settings
from django.db.models import Avg, Sum, Count
from core.models import transaction
from datetime import datetime
from django.template.defaultfilters import stringfilter
import netifaces as ni

# Bağlı olduğunuz ağ arabiriminden IP adresini alın
ip = ni.ifaddresses('enp0s3')[ni.AF_INET][0]['addr']

def instantwallet():
    # Yeni bir cüzdan oluşturur ve gerekli anahtarları döndürür
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    public_key = vk.to_string().hex()
    private_key = sk.to_string().hex()
    keys = [private_key, generate_wallet_from_pkey(public_key), public_key]
    return keys

def generate_wallet_from_pkey(public_key):
    # Genel anahtarın SHA-256 hash'ini alır ve belirli bir uzunluğa kırpılmış bir cüzdan kimliği oluşturur
    binmnmn = public_key.encode('utf-8')
    first_step = 34 - len(settings.CURRENCY)
    wallet_id = hashlib.sha256(binmnmn).hexdigest()
    wallet_id = wallet_id[-first_step:]
    wallet_id = "".join((settings.CURRENCY, wallet_id))
    return wallet_id

def generate_pubkey_from_prikey(private_key):
    # Özel anahtardan genel anahtar oluşturur
    try:
        sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        vk = sk.get_verifying_key()
        print(vk.to_string().hex())
    except UnicodeDecodeError:
        return "Cüzdan bilgilerinizi kontrol edin"
    return vk.to_string().hex()

def addreward():
    # Yeni ödül işlemi ekler
    utc = arrow.utcnow()
    local = utc.to('GMT')
    first_timestamp = local.timestamp
    nonce = miner(first_timestamp, settings.REWARD_HASH, settings.NODE_OWNER_WALLET, 100)
    blockhash = gethash(settings.REWARD_HASH, settings.NODE_OWNER_WALLET, 100, first_timestamp, nonce)
    digitalSignature = json.dumps("reward")
    newtrans = transaction(
        sender=settings.REWARD_HASH,
        senderwallet=settings.REWARD_HASH,
        receiver=settings.NODE_OWNER_WALLET,
        prevblockhash=transaction.objects.all().last().blockhash,
        blockhash=blockhash,
        amount=100,
        nonce=nonce,
        first_timestamp=first_timestamp,
        P2PKH=digitalSignature,
        verification=True
    )
    newtrans.save()
    newtrans.refresh_from_db()
    ip = ni.ifaddresses('enp0s3')[ni.AF_INET][0]['addr']
    geturl = "http://{}/api/v1/gettransaction/{}/".format(ip, newtrans.id)
    test = {
        "server": False,
        "sender": settings.REWARD_HASH,
        "receiver": settings.NODE_OWNER_WALLET,
        "prevblockhash": transaction.objects.all().last().blockhash,
        "blockhash": blockhash,
        "amount": 100,
        "nonce": nonce,
        "timestamp": first_timestamp,
        "P2PKH": digitalSignature,
        "verification": True,
        "block": transaction.objects.all().last().id + 1,
        "message": "new_transaction",
        "url": geturl
    }
    payload = json.dumps(test)
    ws = websocket.WebSocket()
    wsip = "ws://{}:9000".format(ip)
    ws.connect(wsip)
    ws.send(payload)

def miner(first_timestamp, senderwalletid, receiverhex, amount):
    # Blok hash'i için madencilik işlemi
    data = {
        'sender': str(senderwalletid),
        'receiver': str(receiverhex),
        'previous_hash': str(transaction.objects.all().last().blockhash),
        'amount': str(amount),
        'timestamp': str(first_timestamp)
    }
    for nonce in range(0, 10000000):
        data['nonce'] = str(nonce)
        data = collections.OrderedDict(sorted(data.items()))
        datashash = hashlib.sha256(json.dumps(data).encode('utf-8')).hexdigest()
        last2char = datashash[-2:]
        if last2char == "01":
            return nonce
        else:
            continue

def gethash(senderwalletid, receiverhex, amount, first_timestamp, nonce):
    # İşlem verilerinden SHA-256 hash'i alır
    data = {
        'sender': str(senderwalletid),
        'receiver': str(receiverhex),
        'previous_hash': str(transaction.objects.all().last().blockhash),
        'amount': str(amount),
        'timestamp': str(first_timestamp),
        'nonce': str(nonce)
    }
    data = collections.OrderedDict(sorted(data.items()))
    datashash = hashlib.sha256(json.dumps(data).encode('utf-8')).hexdigest()
    return datashash

def checktimepass():
    # Belirli saatlerde işlemlerin yapılmasını kontrol eder
    lasttime = arrow.utcnow().to("GMT")
    gethours, getminute = int(lasttime.format('H')), int(lasttime.format('m'))
    print('hours %s and minutes %s' % (gethours, getminute))
    if gethours == 0 or gethours == 4 or gethours == 8 or gethours == 12 or gethours == 16 or gethours == 20 or gethours == 11:
        return getminute <= 30
    else:
        return False

def checkreward():
    checktime = True  # checktimepass()
    if checktime:
        checklastreward = transaction.objects.filter(sender=settings.REWARD_HASH, receiver=settings.NODE_OWNER_WALLET).last()
        if not checklastreward:
            addreward()
            return "Ağa yeni bir düğüm eklendi"
        else:
            registerd_time = checklastreward.first_timestamp
            oldtime = arrow.get(registerd_time).shift(minutes=+settings.REWARD_TIME).to("GMT").timestamp
            lasttime = arrow.utcnow().to("GMT").timestamp
            if oldtime < lasttime:
                addreward()
                return "Tebrikler, coinlerinizi kazanabilirsiniz " + str(oldtime) + " ve " + str(lasttime)
            else:
                return "Beklemeniz gereken süre: " + str(oldtime) + " ve " + str(lasttime)
    else:
        return "Bekleyin"
