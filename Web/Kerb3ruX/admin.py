from django.contrib import admin
from .models import Slave, Master

admin.site.register(Slave)
admin.site.register(Master)