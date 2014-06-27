import datetime
from django import forms
from django.forms.extras.widgets import SelectDateWidget
from captcha.fields import ReCaptchaField

class DefForm(forms.Form):
    captcha = ReCaptchaField()
    #DataField = forms.DateField(widget=SelectDateWidget)
 
