# -*- coding: utf-8 -*-
import sys, json, requests, django ,os ,base64, collections,hashlib, math, schedule, time
from django.utils.encoding import smart_str
from ecdsa import SigningKey, SECP256k1, NIST384p, BadSignatureError, VerifyingKey
from twisted.internet import reactor
from twisted.python import log
from twisted.web.server import Site
from twisted.web.static import File
import netifaces as ni
from dijicash.wsgi import application as wsgi_handler  # cloudbank -> dijicash olarak değiştirildi
import threading
import queue as Queue
django.setup()
from core.models import transaction
from dijicash.utils import instantwallet, generate_wallet_from_pkey, generate_pubkey_from_prikey, checkreward  # cloudbank -> dijicash olarak değiştirildi

from autobahn.twisted.websocket import WebSocketClientProtocol, \
    WebSocketClientFactory

from autobahn.twisted.websocket import WebSocketServerFactory, \
    WebSocketServerProtocol, \
    listenWS

from autobahn.twisted.websocket import WebSocketClientFactory, \
    WebSocketClientProtocol, \
connectWS

ni.ifaddresses('eth0')
ip = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']


def addnewnode(host):
    ws = "ws://{}:9000".format(host)
    factory = WebSocketClientFactory(ws)
    factory.protocol = MyClientProtocol
    reactor.connectTCP(host, 9000, factory)

# Yeni bir kullanıcı servera bağlandığı zaman bu kısım çalışır.
class BroadcastServerProtocol(WebSocketServerProtocol):

    def onOpen(self):
        self.factory.register(self)

    def onMessage(self, payload, isBinary):
        print(type(payload))
        print(payload)
        print(isBinary)
        if not isBinary:
            print(type(payload))
            myjson = json.loads(payload.decode('utf8'))
            if myjson["server"]:
                print("bu mesaj sunucudan geldi")
                addnewnode(myjson["host"])
            else:
                print(myjson["mesaj"])
                myjson["host"] = ip
                mybinarydata = json.dumps(myjson)
                self.factory.broadcast(mybinarydata.encode('utf8'))
        else:
            myjson = json.loads(payload)
            if myjson["server"]:
                print("bu mesaj sunucudan geldi")
                addnewnode(myjson["host"])
            else:
                print(myjson["mesaj"])
                myjson["host"] = ip
                myjson = json.dumps(myjson)
                self.factory.broadcast(myjson)

    def connectionLost(self, reason):
        WebSocketServerProtocol.connectionLost(self, reason)
        self.factory.unregister(self)

# Kendi içindeki clientlere yayın yapar.
clients = []
class BroadcastServerFactory(WebSocketServerFactory):

    def __init__(self, url):
        WebSocketServerFactory.__init__(self, url)

    def register(self, client):
        if client not in clients:
            if client not in clients:
                print("kayıtlı client {}".format(client.peer))
                print(clients)
                tcp, host, port = client.peer.split(":")
                print(host)
                clients.append(client)

    def unregister(self, client):
        if client in clients:
            print("kayıtlı client {}".format(client.peer))
            clients.remove(client)

    @classmethod
    def broadcast(self, msg):
        for c in clients:
            print(type(msg))
            print(type(msg))
            c.sendMessage(msg)
            print("dışarıdan mesaj aldım {}".format(c.peer))

class MyClientProtocol(WebSocketClientProtocol):
    def onConnect(self, response):
        print("33'ten sunucuya bağlandı': {0}".format(response.peer))

    def onOpen(self):
        print("WebSocket bağlantısı açık.")
        def hello():
            data = {}
            data["server"] = True
            data["host"] = ip
            mybinarydata = json.dumps(data)
            self.sendMessage(mybinarydata.encode('utf8'))
        hello()

    def onMessage(self, payload, isBinary):
        data = {}
        print("onmessage")
        allify = {}
        if isBinary:
            print("Binary mesaj alındı: {0} bytes".format(len(payload)))
        else:
            payloaded = json.loads(payload.decode('utf-8'))
            print(payloaded["host"])
            if str(payloaded["host"]) == str(ip):
                print("bu zaten sensin")
            else:
                payloaded = json.loads(payload.decode('utf-8'))
                if 'sender' in payloaded:
                    data['sender'] = str(payloaded["sender"])
                    data['receiver'] = str(payloaded["receiver"])
                    data['previous_hash'] = str(transaction.objects.all().last().blockhash)
                    data['amount'] = str(payloaded["amount"])
                    data['timestamp'] = str(payloaded["timestamp"])
                    data["nonce"] = str(payloaded["nonce"])
                    data = collections.OrderedDict(sorted(data.items()))
                    datashash  = hashlib.sha256(json.dumps(data).encode('utf-8')).hexdigest()
                    sig = json.loads(payloaded["P2PKH"])
                    print("datahashhere", datashash.encode('utf-8'))
                    print("sigbyte is here", sig)
                    print("sende weas here", payloaded["sender"])
                    wllt = generate_wallet_from_pkey(payloaded["sender"])
                    if(sig == "reward"):
                        newtrans = transaction(sender=payloaded["sender"],
                        senderwallet=wllt,
                        receiver=payloaded["receiver"],
                        prevblockhash=transaction.objects.all().last().blockhash,
                        blockhash=payloaded["blockhash"],
                        amount=payloaded["amount"],
                        nonce=payloaded["nonce"],
                        first_timestamp=payloaded["timestamp"],
                        P2PKH=payloaded["P2PKH"],
                        verification=True
                        ).save()
                    else:
                        try:
                            sigbyte =  bytes.fromhex(sig)
                            vk = VerifyingKey.from_string(bytes.fromhex(payloaded["sender"]), curve=SECP256k1)
                            tt = vk.verify(sigbyte, datashash.encode('utf-8')) # True
                        except BadSignatureError:
                            print("inanılmaz")
                            data["response"] = "inanılmaz"
                            newtrans = transaction(sender=payloaded["sender"],
                            senderwallet=wllt,
                            receiver=payloaded["receiver"],
                            prevblockhash=transaction.objects.all().last().blockhash,
                            blockhash=payloaded["blockhash"],
                            amount=payloaded["amount"],
                            nonce=payloaded["nonce"],
                            first_timestamp=payloaded["timestamp"],
                            P2PKH=payloaded["P2PKH"],
                            verification=False
                            ).save()
                            print("badsignature")

                        newtrans = transaction(sender=payloaded["sender"],
                        senderwallet=wllt,
                        receiver=payloaded["receiver"],
                        prevblockhash=transaction.objects.all().last().blockhash,
                        blockhash=payloaded["blockhash"],
                        amount=payloaded["amount"],
                        nonce=payloaded["nonce"],
                        first_timestamp=payloaded["timestamp"],
                        P2PKH=payloaded["P2PKH"],
                        verification=True
                        ).save()

                else:
                    print("diğer mesaj")
                BroadcastServerFactory.broadcast(payload)

    def onClose(self, wasClean, code, reason):
        print("WebSocket bağlantısı kapandı: {0}".format(reason))
        def byebye():
            self.sendMessage(u"Elveda, 138.68.94.33'ten  !".encode('utf8'))
        byebye()

def syncfirst():
    r = requests.get('http://159.89.197.53/api/v1/alltransactions/')
    alltrans = r.json()
    for x in alltrans["alltestsarecomplated"]:
        try:
            mytransactions = transaction.objects.get(blockhash=x["blockhash"])
        except transaction.DoesNotExist:
            newtrans = transaction(sender=x["sender"],
                senderwallet=x["senderwallet"],
                receiver=x["receiver"],
                prevblockhash=x["prevblockhash"],
                blockhash=x["blockhash"],
                amount=x["amount"],
                nonce=x["nonce"],
                first_timestamp=x["first_timestamp"],
                P2PKH=x["P2PKH"],
                verification=x["verification"])
            newtrans.save()
    print("her şey güncellendi")

if __name__ == '__main__':
    syncfirst()
    ServerFactory = BroadcastServerFactory
    factory = ServerFactory(u"ws://127.0.0.1:9000")
    factory.protocol = BroadcastServerProtocol
    reactor.listenTCP(9000, factory)
    factory = WebSocketClientFactory(u"ws://159.89.197.53:9000")
    factory.protocol = MyClientProtocol
    reactor.connectTCP(u"159.89.197.53", 9000, factory)
    reactor.run()
