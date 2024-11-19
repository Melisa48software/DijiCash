#-*- coding: utf-8 -*-
from django.conf import settings
from django.urls import path
from django.conf.urls.static import static
from django.contrib import admin
import dijicash.views
import dijicash.apilist
from django.conf.urls import url

# Admin sayfasını tanımla
admin.autodiscover()

urlpatterns = [
    # Admin sayfası için URL
    path('admin/', admin.site.urls),
    # Ana sayfa için URL
    path('', dijicash.views.landing),
    # Yeni cüzdan oluşturmak için API
    path('api/v1/createnewwallet/', dijicash.views.createnewwallet),
    
    # Giriş yapmak için URL
    path('login/', dijicash.views.login),
    # Çıkış yapmak için URL
    path('logout/', dijicash.views.logout),
    # İşlemler için WebSocket URL
    path('transactions/', dijicash.views.ws),

    # REST API
    # Cüzdan kontrolü için URL
    path('api/v1/checkwallet/', dijicash.views.checkwallet),
    # Dijital para göndermek için URL
    path('api/v1/sendcloudcoin/', dijicash.views.sendcloudcoin),
    
    # Tüm işlemleri listeleyen API
    path('api/v1/alltransactions/', dijicash.apilist.alltransactions),
    # Belirli bir işlemi getiren API
    path('api/v1/gettransaction/<str:tid>/', dijicash.apilist.gettransaction, name='gettransaction'),
    # Genel anahtar bilgisini almak için API
    path('api/v1/getwalletfrompkey/<str:pkey>/', dijicash.apilist.getwalletfrompkey, name='getwalletfrompkey'),
    # Özel anahtardan genel anahtar bilgisini almak için API
    path('api/v1/getpublickeyfromprikey/<str:private_key>/', dijicash.apilist.getpublickeyfromprikey, name='getpublickeyfromprikey'),
    # Cüzdan bakiyesini almak için API
    path('api/v1/getbalancefromwallet/<str:wallet>/', dijicash.apilist.getbalancefromwallet, name='getbalancefromwallet'),
    # Cüzdan detaylarını almak için API
    path('api/v1/getwalletdetails/<str:wallet>/', dijicash.apilist.getwalletdetails, name='getwalletdetails'),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
