from django.conf.urls import patterns, url

from cves import views

urlpatterns = patterns('',
    url(r'^(?P<cve_id>[\w-]+)/annotate$', views.annotate_cve, name='annotate_cve')
)
