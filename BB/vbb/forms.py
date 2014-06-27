from django import forms

class VoteForm(forms.Form):
    serial = forms.CharField(max_length=1024)
    code = forms.CharField(max_length=1024)

class FeedbackForm(forms.Form):
    checkcode = forms.CharField(max_length=1024)
    checkoption = forms.CharField(max_length=1024)
