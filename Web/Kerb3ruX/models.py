from django.db import models

class Master(models.Model):
    uid         = models.CharField(max_length=32, null=False)
    platform    = models.CharField(max_length=30, null=False)
    name        = models.CharField(max_length=50, null=False)
    passphrese  = models.CharField(max_length=16, null=False)

class Slave(models.Model):
    uid         = models.CharField(max_length=32, null=False)
    country     = models.CharField(max_length=10, null=False)
    latitude    = models.FloatField(null=False) # [-90, +90]
    longitude   = models.FloatField(null=False) # [-180, +180]
    ip          = models.GenericIPAddressField(null=False)
    superuser   = models.BooleanField(null=False)
    master      = models.ForeignKey(Master, on_delete=models.CASCADE, null=False)
    last_report = models.DateField(null=False)
