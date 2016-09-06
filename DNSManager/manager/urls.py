from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.contrib.auth import views as auth_views
from rest_framework.urlpatterns import format_suffix_patterns
from manager import views as manager_views


admin.autodiscover()


urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'DNSManager.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    url(r'^/?$', 'manager.views.index', name='index'),
    url(r'^login/?$', 'manager.views.login_page', name='login'),
    url(r'^logout/?$', 'manager.views.login_page', name='logout'),

    url(r'^user/password/?$', auth_views.password_change, {'template_name': 'manager/user_password.html'}, name="change_password"),
    url(r'^user/password/changed/?$', 'manager.views.password_changed', name='password_change_done'),

    url(r'^domains/add/?$', "manager.views.add_domain", name="add_domain"),
    url(r'^domains/(?P<name>[a-zA-Z0-9\.\-]+)/edit/?$', "manager.views.edit_domain", name="edit_domain"),
    url(r'^domains/(?P<domain>[a-zA-Z0-9\.\-]+)/add_static/?$', "manager.views.add_static", name="add_static"),
    url(r'^domains/(?P<domain>[a-zA-Z0-9\.\-]+)/edit_static/(?P<entry>\d+)/?$', "manager.views.edit_static", name="edit_static"),
    url(r'^domains/(?P<domain>[a-zA-Z0-9\.\-]+)/delete_static/(?P<entry>\d+)/?$', "manager.views.delete_static", name="delete_static"),
    url(r'^domains/(?P<domain>[a-zA-Z0-9\.\-]+)/sync/?$', "manager.views.synchronize_domain", name="sync_domain"),
    url(r'^domains/(?P<name>[a-zA-Z0-9\.\-]+)/?$', "manager.views.show_domain", name="show_domain"),

    url(r'^dyndns/edit/(?P<id>[0-9]+)$', "manager.views.edit_dyndns", name="edit_dyndns"),
    url(r'^dyndns/sync/(?P<id>[0-9]+)$', "manager.views.synchronize_dyndns", name="sync_dyndns"),
    url(r'^dyndns/delete/(?P<id>[0-9]+)$', "manager.views.delete_dyndns", name="delete_dyndns"),
    url(r'^dyndns/edit/(?P<id>[0-9]+)/secret$', "manager.views.edit_dyndns_secret", name="edit_dyndns_secret"),
    url(r'^dyndns/add/(?P<name>[a-zA-Z0-9\.\-]+)$', "manager.views.add_dyndns", name="add_dyndns"),
    url(r'^api/update/(?P<secret>[a-zA-Z0-9]+)$', 'manager.views.update', name="api_update"),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^user/reset_password/', include('password_reset.urls')),


) + format_suffix_patterns(
    (
        url(r'^rest/v1/domains/$', manager_views.DomainList.as_view(), name="api_domain_list"),
        url(r'^rest/v1/domains/(?P<pk>[0-9]+)/?$', manager_views.DomainDetail.as_view(), name="api_domain_detail"),
        url(r'^rest/v1/domains/(?P<domain_id>[0-9]+)/records/?$', manager_views.RecordList.as_view()),
        url(r'^rest/v1/domains/(?P<domain_id>[0-9]+)/records/(?P<pk>[0-9]+)$', manager_views.RecordDetail.as_view()),
        url(r'^rest/v1/domains/(?P<domain_id>[0-9]+)/dyndns/?$', manager_views.DynDNSList.as_view()),
        url(r'^rest/v1/domains/(?P<domain_id>[0-9]+)/dyndns/(?P<pk>[0-9]+)/?$', manager_views.DynDNSClient.as_view()),
    )
)

