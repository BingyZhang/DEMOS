from django.conf.urls import patterns, include, url
from django.conf.urls.static import static
from django.conf import settings
from django.contrib import admin
#from abb import views
admin.autodiscover()

urlpatterns = patterns('',
    url(r'^vbb/', include('vbb.urls')),
    url(r'^abb/', include('abb.urls')),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^def/', 'abb.views.init'),
    url(r'^keyholder/(?P<eid>\w+)/(?P<salt>\w+)/$', 'vbb.views.keyholder'),
    url(r'^test/(?P<eid>\w+)/$', 'vbb.views.test'),
    url(r'^thanks/$', 'vbb.views.thanks'),
) + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
