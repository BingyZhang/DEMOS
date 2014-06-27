from django.conf.urls import patterns, url

from vbb import views

urlpatterns = patterns('',
    url(r'^(?P<eid>\w+)/$', views.index),
    url(r'^(?P<eid>\w+)/client/$', views.client),
    url(r'^(?P<eid>\w+)/export/$', views.export),
    url(r'^(?P<eid>\w+)/upload/$', views.upload),                   
    url(r'^$', views.empty)
)
