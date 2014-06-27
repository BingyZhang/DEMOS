from django.conf.urls import patterns, url
from abb import views

urlpatterns = patterns('',
    url(r'^(?P<eid>\w+)/$', views.index),
    url(r'^(?P<eid>\w+)/(?P<tab>\d+)/$', views.index), 
    url(r'^(?P<eid>\w+)/(?P<tab>\d+)/(?P<page>\d+)/$', views.scroll),                   
    url(r'^(?P<eid>\w+)/upload/$', views.upload),
    url(r'^$', views.empty),                  
)
