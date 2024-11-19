"""
WSGI konfigürasyonu - dijicash projesi.

Bu dosya, WSGI çağrılabilirini modül düzeyinde bir değişken olan ``application`` olarak ortaya çıkarır.

Bu dosya hakkında daha fazla bilgi için
https://docs.djangoproject.com/en/5.0/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dijicash.settings')

application = get_wsgi_application()
