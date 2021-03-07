from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """ Custom User Model"""
    id = models.AutoField(primary_key=True)
    avatar = models.ImageField(upload_to="avatars", blank=True)
    superhost = models.BooleanField(default=False)
    favs = models.ManyToManyField("rooms.Room", related_name="favs")

    def room_count(self):
        return self.rooms.count()

    room_count.short_description = "Room Count"
