#-*- coding: utf-8 -*-
import uuid , json , string , random, urllib, base64, os, sys, time, pickle, collections, math, arrow
from django.utils.encoding import smart_str
from ecdsa import SigningKey, SECP256k1, NIST384p, BadSignatureError, VerifyingKey
from django.http import *
from django import template
from django.shortcuts import *
from django.http import HttpResponse
from django.contrib.auth import logout
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.conf import settings
from dijicash.utils import instantwallet, generate_wallet_from_pkey, generate_pubkey_from_prikey, checkreward
from django.db.models import Avg, Sum, Count
import base64, bson, websocket, hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import logging
from core.models import transaction
#import sha256

import json
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from core.models import transaction
from django.template.defaultfilters import stringfilter
import netifaces as ni
ip = ni.ifaddresses('enp0s3')[ni.AF_INET][0]['addr']

def landing(request):
    try:
        pubkey = request.session['pubkey']
        prikey = request.session['prikey']
        print(pubkey)
        print(pubkey.encode('utf-8'))
        print(type(pubkey.encode('utf-8')))
        wallet_id =  generate_wallet_from_pkey(pubkey) #hashlib.sha256(pubkey.encode('utf-8')).hexdigest() #SHA256.new(pubkey).hexdigest()
        balance = getbalance(pubkey)
        if balance is None:
            balance = 0
        return render(request, "ok.html", locals())
    except KeyError:
        return render(request, "index.html", locals())
    
    
def login(request):
    try:
        pubkey = request.session['pubkey']
        prikey = request.session['prikey']
        return HttpResponseRedirect('/')
    except KeyError:
        return render(request, "login.html", locals())

def logout(request):
    request.session.clear()
    return HttpResponseRedirect('/')
    
def generate_key_pair():
    # Genel ve özel anahtar çiftini oluştur
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    return public_key, private_key

def calculate_hash(data):
    # Verinin SHA-256 hash'i hesaplanır
    return hashlib.sha256(data).hexdigest()

def createnewwallet(request):
    # Anahtar çifti oluşturulur
    public_key, private_key = generate_key_pair()

    # Public key'in hash'i hesaplanır
    public_key_hash = calculate_hash(public_key.export_key())

    # Data sözlüğü oluşturulur
    data = {
        "public_key": base64.b64encode(public_key.export_key()).decode('utf-8'),
        "private_key": base64.b64encode(private_key.export_key()).decode('utf-8'),
        "public_key_hash": public_key_hash
    }
    # Çıktıyı düzgün formatta oluştur
    output = f"Public Key:\n{public_key.export_key().decode('utf-8')}\n\nPrivate Key:\n{private_key.export_key().decode('utf-8')}\n\nHash:\n{public_key_hash}"

    return HttpResponse(output, content_type="text/plain")

    #return HttpResponse(json.dumps(data), content_type="application/json")

@csrf_exempt
def checkwallet(request):
    data = {}
    
    prikey64 = request.POST.get('prikey').strip()
    pubkey64 = request.POST.get('pubkey').strip()
    
    # BASE64 kodunu çöz ve ardından hex formata çevir
    prikey = base64.b64decode(prikey64).hex()
    pubkey = base64.b64decode(pubkey64).hex()

    message = "yeyy"

    try:
        # Önce private ve public key'leri RSA objelerine çevirelim
        private_key = RSA.import_key(bytes.fromhex(prikey))
        public_key = RSA.import_key(bytes.fromhex(pubkey))

        # Şifreleme işlemi
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = cipher.encrypt(message.encode('utf-8'))

        # Çözme işlemi
        decipher = PKCS1_OAEP.new(private_key)
        decrypted_message = decipher.decrypt(ciphertext).decode('utf-8')

        # Şifreleme ve çözme işlemleri doğruysa devam edelim
        if decrypted_message == message:
            data["response"] = "access_approved"
            request.session['pubkey'] = pubkey
            request.session['prikey'] = prikey
        else:
            data["response"] = "access_denied"
    except ValueError as ve:
        data["response"] = f"Check your wallet details: {ve}"
    except TypeError as te:
        data["response"] = f"Check your wallet details: {te}"
    except (SyntaxError, IndexError) as se:
        data["response"] = f"Check your wallet details: {se}"
    except Exception as e:
        data["response"] = f"Check your wallet details: {str(e)}"

    return HttpResponse(json.dumps(data), content_type="application/json")

def getbalance(pubkey):
    try:
        wallet_id = generate_wallet_from_pkey(pubkey)
        outgoing = transaction.objects.filter(sender=pubkey).aggregate(Sum('amount'))['amount__sum']
        income = transaction.objects.filter(receiver=wallet_id).aggregate(Sum('amount'))['amount__sum']
        
        if income is not None and outgoing is not None:
            balance = income - outgoing
            return max(0, balance)
        elif outgoing is None:
            return max(0, income) if income is not None else 0
        elif income is None:
            return 0
        else:
            return 0
    except Exception as e:
        # Hata durumunu ele al
        print(f"Error: {str(e)}")
        return 0
    
def miner(first_timestamp, senderwalletid, receiverhex, amount):
    data = {}
    for nonce in range(0,10000000):
        data['sender'] = str(senderwalletid)                                        #1
        data['receiver'] = str(receiverhex)                                         #2
        data['previous_hash'] =  str(transaction.objects.all().last().blockhash)    #3
        data['amount'] = str(amount)                                                #4
        data['timestamp'] =  str(first_timestamp)                                   #5
        data["nonce"] = str(nonce)
        data = collections.OrderedDict(sorted(data.items()))
        datashash  = hashlib.sha256(json.dumps(data).encode('utf-8')).hexdigest()
        last2char = datashash[-2:]
        if last2char == "01":
            return(nonce)
        else:
            continue
    
@csrf_exempt
def senddijicash(request):
    allify = {}
    data = {}
    if request.method == 'POST':
        senderprivatekey = request.POST.get('sprikey')
        receiverwallet = request.POST.get('receiverwallet').strip()
        amount = request.POST.get('amount').strip()
        sender = generate_pubkey_from_prikey(senderprivatekey)
        #print(checkreward())
        if not receiverwallet:
            allify['response'] = "fail"
            allify['explain'] = "Please fill the receiver box"
            return HttpResponse(json.dumps(allify), content_type="application/json")
        try:
            amount = int(request.POST.get('amount').strip())
        except ValueError:
            allify['response'] = "fail"
            allify['explain'] = "Please fill the balance box"
            return HttpResponse(json.dumps(allify), content_type="application/json")
        if int(amount) <= 0:
            allify['response'] = "fail"
            allify['explain'] = "insufficient balance"
            return HttpResponse(json.dumps(allify), content_type="application/json")
        balance = getbalance(sender)
        if balance is None:
            balance = 0
        if int(amount) > int(balance):
            allify['response'] = "fail"
            allify['explain'] = "insufficient balance"
            return HttpResponse(json.dumps(allify), content_type="application/json")
        else:
            utc = arrow.utcnow()
            local = utc.to('GMT')
            first_timestamp = local.timestamp
            data['sender'] = str(sender)                                                    #1
            data['receiver'] = str(receiverwallet)                                          #2
            data['previous_hash'] = str(transaction.objects.all().last().blockhash)         #3
            data['amount'] = str(amount)                                                    #4
            data['timestamp'] = str(first_timestamp)                                        #5
            perfect =  miner(first_timestamp, sender, receiverwallet, amount)
            data["nonce"] = str(perfect)
            data = collections.OrderedDict(sorted(data.items()))
            datashash  = hashlib.sha256(json.dumps(data).encode('utf-8')).hexdigest()
            #print(checkreward())
            try:
                sk = SigningKey.from_string(bytes.fromhex(senderprivatekey), curve=SECP256k1)
                vk = sk.get_verifying_key() #public_key
                print(vk.to_string().hex())
            except UnicodeDecodeError:
                data["response"] = "Check your wallet details"
                return HttpResponse(json.dumps(data), content_type="application/json")
            print("digital sign ishere", datashash.encode('utf-8'))
            digitalSignature = sk.sign(datashash.encode('utf-8'))
            digitalSignature = json.dumps(digitalSignature.hex())

            wllt = generate_wallet_from_pkey(sender)
            newtrans = transaction(sender=sender,
            senderwallet=wllt,
            receiver=receiverwallet,
            prevblockhash=transaction.objects.all().last().blockhash,
            blockhash=datashash,
            amount=amount,
            nonce=perfect,
            first_timestamp=first_timestamp,
            P2PKH=digitalSignature,
            verification=True
            )
            newtrans.save()
            ip = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
            geturl = "http://{}/api/v1/gettransaction/{}/".format(ip, newtrans.id)
            test = {"server":False,
            "sender":sender,
            "receiver":receiverwallet,
            "prevblockhash":transaction.objects.all().last().blockhash,
            "blockhash":datashash,
            "amount":amount,
            "nonce":perfect,
            "timestamp":first_timestamp,
            "P2PKH":digitalSignature,
            "verification":True,
            "block" : transaction.objects.all().last().id + 1,
            "message":"new_transaction",
            "url":geturl}

            payload = json.dumps(test)

            ws = websocket.WebSocket()
            wsip = "ws://{}:9000".format(ip)
            ws.connect(wsip)
            ws.send(payload)

            allify['response'] = "ok"
            allify['explain'] = "You currency transferred successfully"

            allify['datashash'] = datashash
            allify['datastring'] = json.dumps(allify)
            return HttpResponse(json.dumps(allify), content_type="application/json")
