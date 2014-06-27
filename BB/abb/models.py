from django.db import models
from vbb.models import Election

# Create your models here.

class Auxiliary(models.Model):
    election = models.ForeignKey(Election)
    tallyplain = models.TextField(null=True, blank=True)
    tallydecom = models.TextField(null=True, blank=True)
    tallycipher = models.TextField(null=True, blank=True)
    verify = models.BooleanField(default=False)

class AbbKey(models.Model):
    table = models.IntegerField(default=0)
    column = models.IntegerField(default=0)
    plaintext = models.CharField(max_length=2048,null=True, blank=True)
    commitment = models.CharField(max_length=2048,null=True, blank=True)
    decommitment = models.CharField(max_length=2048,null=True, blank=True)
    election = models.ForeignKey(Election)
    version = models.IntegerField(default=0)   
    def __unicode__(self):
        return "Table "+str(self.table)+" Ver. "+ str(self.version)
    
class AbbData(models.Model):
    table = models.IntegerField(default=0)
    column = models.IntegerField(default=0)
    length = models.IntegerField(default=0)
    ciphertext = models.TextField(null=True, blank=True)
    plaintext = models.TextField(null=True, blank=True)
    election = models.ForeignKey(Election)
    version = models.IntegerField(default=0)   
    def __unicode__(self):
        return "Table "+str(self.table)+" Ver. "+ str(self.version)    

class UpdateInfo(models.Model):
    table = models.IntegerField(null=True, blank=True)
    text = models.CharField(max_length=2048,null=True, blank=True)
    election = models.ForeignKey(Election)
    date = models.DateTimeField(auto_now_add=True)
    file = models.FileField(upload_to='Archives/op_files',null=True, blank=True)
    sig = models.FileField(upload_to='Archives/signatures',null=True, blank=True)
    def __unicode__(self):
        return "Op: "+str(self.text)+" Date: "+ str(self.date)

class Abbinit(models.Model):
    election = models.ForeignKey(Election)
    serial = models.CharField(max_length=1024)
    codes1 = models.TextField(null=True, blank=True)
    enc1 = models.TextField(null=True, blank=True)
    codes2 = models.TextField(null=True, blank=True)
    enc2 = models.TextField(null=True, blank=True)
    cipher1 = models.TextField(null=True, blank=True)
    cipher2 = models.TextField(null=True, blank=True)
    ZKone1 = models.TextField(null=True, blank=True)
    ZKone2 = models.TextField(null=True, blank=True)
    ZKtwo1 = models.TextField(null=True, blank=True)
    ZKtwo2 = models.TextField(null=True, blank=True)
    zeroone = models.TextField(null=True, blank=True)
    mark1 = models.TextField(null=True, blank=True)
    mark2 = models.TextField(null=True, blank=True)
    rand1 = models.TextField(null=True, blank=True)
    rand2 = models.TextField(null=True, blank=True)
    plain1 = models.TextField(null=True, blank=True)
    plain2 = models.TextField(null=True, blank=True)
    ZKstate1 = models.TextField(null=True, blank=True)
    ZKstate2 = models.TextField(null=True, blank=True)
    decom1 = models.TextField(null=True, blank=True)
    decom2 = models.TextField(null=True, blank=True)
