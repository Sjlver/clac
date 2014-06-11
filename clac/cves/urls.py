from django.conf.urls import patterns, url

from cves import views

urlpatterns = patterns('',
    url(r'^(?P<cve_id>[\w-]+)/annotate$', views.annotate_cve, name='annotate_cve'),
    url(r'^random$', views.random_cve, name='random_cve'),
    url(r'^summary$', views.summary, name='summary'),
    url(r'^login$', views.login, name='login'),
    url(r'^logout$', views.logout, name='logout'),
    url(r'^$', views.index, name='index'),
)
