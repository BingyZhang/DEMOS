from django.conf.urls import patterns, url

from elect_def import views

urlpatterns = patterns('',
    url(r'^(?P<eid>\w+)/$', views.TBA),
    url(r'^$', views.index),
)
