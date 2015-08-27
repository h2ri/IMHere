from oauth2_provider.models import Application
from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_save


class MyUser(models.Model):
    user = models.OneToOneField(User)
    date_of_birth = models.DateField()
    
    def create_auth_client(sender, instance=None, created=False, **kwargs):
            if created:
                Application.objects.create(user=instance,                             client_type=Application.CLIENT_CONFIDENTIAL,
                                authorization_grant_type=Application.GRANT_PASSWORD)
    
    post_save.connect(create_auth_client, sender=User)

