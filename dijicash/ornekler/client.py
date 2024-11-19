###############################################################################
#
# The MIT License (MIT)
#
# Copyright (c) typedef int GmbH
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
###############################################################################

import sys
from twisted.internet import reactor
from autobahn.twisted.websocket import WebSocketClientFactory, \
    WebSocketClientProtocol, \
    connectWS

class BroadcastClientProtocol(WebSocketClientProtocol):
    """
    WebSocket sunucusuna bağlanan, her 2 saniyede bir HELLO mesajı gönderen
    ve aldığı her şeyi yazdıran basit bir istemci.
    """

    def sendHello(self):
        self.sendMessage("Hello from Python!".encode('utf8'))
        reactor.callLater(2, self.sendHello)

    def onOpen(self):
        self.sendHello()

    def onMessage(self, payload, isBinary):
        if not isBinary:
            print("Text message received: {}".format(payload.decode('utf8')))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("WebSocket sunucu adresine ihtiyaç var, örn. ws://127.0.0.1:9000")
        sys.exit(1)

    factory = WebSocketClientFactory(sys.argv[1])
    factory.protocol = BroadcastClientProtocol
    connectWS(factory)

    reactor.run()
