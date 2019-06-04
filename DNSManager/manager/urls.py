from django.urls import include, path, re_path
from django.contrib import admin
from django.contrib.auth import views as auth_views
from rest_framework.urlpatterns import format_suffix_patterns

import manager.views
from manager import views as manager_views


admin.autodiscover()


urlpatterns = [
    path('', manager.views.index, name='index'),
    re_path(r'^login/?$', manager.views.login_page, name='login'),
    re_path(r'^logout/?$', manager.views.login_page, name='logout'),

    re_path(r'^user/password/?$', auth_views.PasswordChangeView, {'template_name': 'manager/user_password.html'}, name="change_password"),
    re_path(r'^user/password/changed/?$', manager.views.password_changed, name='password_change_done'),

    re_path(r'^domains/add/?$', manager.views.add_domain, name="add_domain"),
    re_path(r'^domains/(?P<name>[a-zA-Z0-9\.\-]+)/edit/?$', manager.views.edit_domain, name="edit_domain"),
    re_path(r'^domains/(?P<domain>[a-zA-Z0-9\.\-]+)/add_static/?$', manager.views.add_static, name="add_static"),
    re_path(r'^domains/(?P<domain>[a-zA-Z0-9\.\-]+)/edit_static/(?P<entry>\d+)/?$', manager.views.edit_static, name="edit_static"),
    re_path(r'^domains/(?P<domain>[a-zA-Z0-9\.\-]+)/delete_static/(?P<entry>\d+)/?$', manager.views.delete_static, name="delete_static"),
    re_path(r'^domains/(?P<domain>[a-zA-Z0-9\.\-]+)/sync/?$', manager.views.synchronize_domain, name="sync_domain"),
    re_path(r'^domains/(?P<name>[a-zA-Z0-9\.\-]+)/?$', manager.views.show_domain, name="show_domain"),

    re_path(r'^dyndns/edit/(?P<id>[0-9]+)$', manager.views.edit_dyndns, name="edit_dyndns"),
    re_path(r'^dyndns/sync/(?P<id>[0-9]+)$', manager.views.synchronize_dyndns, name="sync_dyndns"),
    re_path(r'^dyndns/delete/(?P<id>[0-9]+)$', manager.views.delete_dyndns, name="delete_dyndns"),
    re_path(r'^dyndns/edit/(?P<id>[0-9]+)/secret$', manager.views.edit_dyndns_secret, name="edit_dyndns_secret"),
    re_path(r'^dyndns/add/(?P<name>[a-zA-Z0-9\.\-]+)$', manager.views.add_dyndns, name="add_dyndns"),
    re_path(r'^api/update/(?P<secret>[a-zA-Z0-9]+)$', manager.views.update, name="api_update"),
    re_path(r'^user/reset_password/', include('password_reset.urls')),
    path('admin/', admin.site.urls),


] + format_suffix_patterns(
    (
        re_path(r'^rest/v1/domains/$', manager_views.DomainList.as_view(), name="api_domain_list"),
        re_path(r'^rest/v1/domains/(?P<pk>[0-9]+)/?$', manager_views.DomainDetail.as_view(), name="api_domain_detail"),
        re_path(r'^rest/v1/domains/(?P<domain_id>[0-9]+)/records/?$', manager_views.RecordList.as_view()),
        re_path(r'^rest/v1/domains/(?P<domain_id>[0-9]+)/records/(?P<pk>[0-9]+)$', manager_views.RecordDetail.as_view()),
        re_path(r'^rest/v1/domains/(?P<domain_id>[0-9]+)/dyndns/?$', manager_views.DynDNSList.as_view()),
        re_path(r'^rest/v1/domains/(?P<domain_id>[0-9]+)/dyndns/(?P<pk>[0-9]+)/?$', manager_views.DynDNSClient.as_view()),
    )
)
