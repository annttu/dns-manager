from django.conf.urls import patterns, include, url
from django.contrib import admin

admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'DNSManager.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    url(r'^/?$', 'manager.views.index', name='index'),
    url(r'^login/?$', 'manager.views.login_page', name='login'),
    url(r'^logout/?$', 'manager.views.login_page', name='logout'),

    url(r'^domains/add/?$', "manager.views.add_domain", name="add_domain"),
    url(r'^domains/(?P<name>[a-zA-Z0-9\.\-]+)/edit/?$', "manager.views.edit_domain", name="edit_domain"),
    url(r'^domains/(?P<domain>[a-zA-Z0-9\.\-]+)/add_static/?$', "manager.views.add_static", name="add_static"),
    url(r'^domains/(?P<domain>[a-zA-Z0-9\.\-]+)/edit_static/(?P<entry>\d+)/?$', "manager.views.edit_static", name="edit_static"),
    url(r'^domains/(?P<domain>[a-zA-Z0-9\.\-]+)/delete_static/(?P<entry>\d+)/?$', "manager.views.delete_static", name="delete_static"),
    url(r'^domains/(?P<domain>[a-zA-Z0-9\.\-]+)/sync/?$', "manager.views.synchronize_domain", name="sync_domain"),
    url(r'^domains/(?P<name>[a-zA-Z0-9\.\-]+)/?$', "manager.views.show_domain", name="show_domain"),

    url(r'^dyndns/edit/(?P<id>[0-9]+)$', "manager.views.edit_dyndns", name="edit_dyndns"),
    url(r'^dyndns/delete/(?P<id>[0-9]+)$', "manager.views.delete_dyndns", name="delete_dyndns"),
    url(r'^dyndns/edit/(?P<id>[0-9]+)/secret$', "manager.views.edit_dyndns_secret", name="edit_dyndns_secret"),
    url(r'^dyndns/add/(?P<name>[a-zA-Z0-9\.\-]+)$', "manager.views.add_dyndns", name="add_dyndns"),
    url(r'^api/update/(?P<secret>[a-zA-Z0-9]+)$', 'manager.views.update', name="api_update"),
    url(r'^admin/', include(admin.site.urls)),
)
