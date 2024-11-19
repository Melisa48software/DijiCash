"""
ASGI konfigürasyonu - dijicash projesi.

Bu dosya, ASGI çağrılabilirini modül düzeyinde bir değişken olan ``application`` olarak ortaya çıkarır.

Bu dosya hakkında daha fazla bilgi için
https://docs.djangoproject.com/en/5.0/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dijicash.settings')

application = get_asgi_application()
