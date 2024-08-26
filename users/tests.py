from django.contrib.auth.models import User
from django.test import TestCase

user = User.objects.create_user('test', '<EMAIL>', '1411')

user.save()
