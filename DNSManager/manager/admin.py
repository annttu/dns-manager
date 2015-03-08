from django.contrib import admin
from .models import *


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    pass


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    pass

