from django.conf.urls import patterns, include, url
from django.conf.urls.static import static
from django.conf import settings
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    url(r'^bds/', 'auth.views.login'),
    url(r'^vote/(?P<eid>\w+)/$', 'auth.views.vote'),
    url(r'^client/(?P<eid>\w+)/(?P<token>\w+)/$', 'auth.views.client'),
    url(r'^def/', include('elect_def.urls')),
   # url(r'^publicdef/', 'elect_def.views.pubdef'),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^pdf/(?P<eid>\w+)/(?P<token>\w+)/$', 'auth.views.pdfballot'),
url(r'^sample/(?P<eid>\w+)/(?P<token>\w+)/(?P<side>\w+)/$', 'auth.views.sample'),
) + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
