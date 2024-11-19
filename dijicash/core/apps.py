from django.apps import AppConfig

class CoreConfig(AppConfig):
    # Otomatik alan oluşturucu olarak BigAutoField kullan
    default_auto_field = 'django.db.models.BigAutoField'
    # Uygulama adı 'core'
    name = 'core'
