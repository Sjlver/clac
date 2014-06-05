from django.conf.urls import patterns, include, url

from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'clac.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),

    url(r'^cves/', include('cves.urls')),
    url(r'^admin/', include(admin.site.urls)),

    url(r'^', 'cves.views.index'),
)
