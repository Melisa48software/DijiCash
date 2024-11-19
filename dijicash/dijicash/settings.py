"""
Django ayarları - dijicash projesi.

Django 5.0.1 sürümü kullanılarak 'django-admin startproject' komutu ile oluşturuldu.

Bu dosya hakkında daha fazla bilgi için
https://docs.djangoproject.com/en/5.0/topics/settings/

Tüm ayarlar ve değerleri için
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

from pathlib import Path
import os

# Projedeki dosya yollarını oluştur: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Para birimi tanımı
CURRENCY = "4A"

# Hızlı başlangıç geliştirme ayarları - üretime uygun değil
# https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# GÜVENLİK UYARISI: Üretimde kullanılan gizli anahtarı saklayın!
SECRET_KEY = 'django-insecure-$9d$=!gzb6c&0z^=7hjt%k7-^(znibph3rljcdrb8a162^3yhc'

# GÜVENLİK UYARISI: Üretimde hata ayıklama açık olmamalıdır!
DEBUG = True

ALLOWED_HOSTS = ['localhost', '192.168.43.172', '192.168.1.10', '192.168.1.102']

# Uygulama tanımları
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',
    'core',
    
    'django_celery_results',
    'django_celery_beat',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'dijicash.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'dijicash/templates/htmlfiles')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'dijicash.wsgi.application'

# Veritabanı
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

# Şifre doğrulama
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Uluslararasılaştırma
LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'GMT'

USE_I18N = True

USE_L10N = True

USE_TZ = True

# STATİCFILES_DIRS = [os.path.join(BASE_DIR, 'static')]

# Statik dosyalar (CSS, JavaScript, Resimler)
# https://docs.djangoproject.com/en/1.11/howto/static-files/

STATIC_URL = '/static/'

MEDIA_ROOT = os.path.join(os.path.dirname(__file__), 'dijicash/templates/media_cdn')
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
# STATIC_ROOT = os.path.join(PROJECT_DIR, 'templates/static')
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "dijicash/templates/static"),
]
