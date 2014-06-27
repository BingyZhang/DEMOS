from django.contrib import admin
from abb.models import AbbKey,AbbData, UpdateInfo, Auxiliary, Abbinit


# Register your models here.
class AbbKeyAdmin(admin.ModelAdmin):
    list_display = ('table', 'version','column', 'commitment', 'plaintext', 'decommitment')
    list_filter = ['table']
    search_fields = ['column']

class AbbDataAdmin(admin.ModelAdmin):
    list_display = ('table', 'version','column', 'ciphertext', 'plaintext')
    list_filter = ['table']
    search_fields = ['column']    

class AuxiliaryAdmin(admin.ModelAdmin):
    list_display = ('verify','tallycipher','tallyplain')   

class UpdateInfoAdmin(admin.ModelAdmin):
    list_display = ('text', 'date')


class AbbinitAdmin(admin.ModelAdmin):
    list_display = ('serial', 'enc1','enc2')
    list_filter = ['election']
    search_fields = ['serial']

admin.site.register(Auxiliary, AuxiliaryAdmin)
admin.site.register(AbbKey, AbbKeyAdmin)
admin.site.register(AbbData, AbbDataAdmin)
admin.site.register(UpdateInfo, UpdateInfoAdmin)
admin.site.register(Abbinit, AbbinitAdmin)
