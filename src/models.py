from django.db import models

#from django.contrib.auth.models import User



class User(models.Model):
    username = models.TextField()
    password = models.TextField()

class Comment(models.Model):
    comment_text = models.TextField()
    pub_date = models.DateField('date published')
    by = models.ForeignKey(User, on_delete=models.CASCADE)


class AccessToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.TextField()
