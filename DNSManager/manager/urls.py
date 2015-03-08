from django.conf.urls import patterns, include, url
from django.contrib import admin

admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'DNSManager.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    url(r'^/?$', 'manager.views.index', name='index'),
    url(r'^api/update/(?P<secret>[a-zA-Z0-9]+)$', 'manager.views.update', name="update"),
    url(r'^admin/', include(admin.site.urls)),
)
