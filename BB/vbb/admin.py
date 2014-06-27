from django.contrib import admin
from vbb.models import Election, Choice, Vbb, Dballot, Bba, Randomstate,Keyholder


# Register your models here.
class VbbAdmin(admin.ModelAdmin):
    list_display = ('serial', 'votecode','date')
    list_filter = ['election']
    search_fields = ['serial']

class DballotAdmin(admin.ModelAdmin):
    list_display = ('serial', 'code', 'value')
    list_filter = ['vbb']
    search_fields = ['serial']

class ElectionAdmin(admin.ModelAdmin):
    list_display = ('question', 'start', 'end')
    list_filter = ['question']
    search_fields = ['question']

class ChoiceAdmin(admin.ModelAdmin):
    list_display = ['text']
    list_filter = ['election']
    search_fields = ['text']

class BbaAdmin(admin.ModelAdmin):
    list_display = ['serial','key']
    list_filter = ['election']
    search_fields = ['serial']

class RandomAdmin(admin.ModelAdmin):
    list_display = ['notes','random']
    list_filter = ['election']
    search_fields = ['notes']

class KeyholderAdmin(admin.ModelAdmin):
    list_display = ['email','hash']
    list_filter = ['election']
    search_fields = ['email']

admin.site.register(Keyholder, KeyholderAdmin)
admin.site.register(Vbb, VbbAdmin)
admin.site.register(Bba, BbaAdmin)
admin.site.register(Election, ElectionAdmin)
admin.site.register(Choice, ChoiceAdmin)
admin.site.register(Dballot, DballotAdmin)
admin.site.register(Randomstate, RandomAdmin)
