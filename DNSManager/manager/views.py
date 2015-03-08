from django.contrib import messages
from django.contrib.auth import logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import login
from django.core.urlresolvers import reverse
from django.shortcuts import render_to_response, redirect
from django.template import RequestContext
from django.http import JsonResponse, HttpResponseRedirect, Http404, HttpRequest
from .models import Client, Domain, TSIG_KEY_TYPES
from .forms import DomainForm, ClientForm, ClientEditForm
from utils import hash_password, gen_password
import socket
import logging
import dnsutils


logger = logging.getLogger('manager.views')


def login_page(request):
    logout(request)
    username = password = ''
    if request.POST:
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                return HttpResponseRedirect('/')
    return render_to_response('manager/login.html',
                              context_instance=RequestContext(request))

@login_required(login_url='/login')
def index(request):
    domains = Domain.objects.filter(users__pk = request.user.pk).all()
    return render_to_response('manager/index.html', {'domains': domains},
                              context_instance=RequestContext(request))

@login_required
def edit_domain(request, name):
    try:
        domain = Domain.objects.get(name=name, users__pk=request.user.pk)
    except Domain.DoesNotExist:
        raise Http404

    return render_to_response('manager/edit_domain.html', {'domain': domain, 'key_types': TSIG_KEY_TYPES},
                              context_instance=RequestContext(request))

@login_required
def add_domain(request):
    if request.method == 'POST':
        instance = Domain()
        f = DomainForm(request.POST, initial={'users': [request.user]}, instance=instance)
        if f.is_valid():
            domain = f.save()
            domain.users.add(request.user)
            domain.save()
            messages.success(request, "Successfully added domain %s" % (f.cleaned_data['name']))
            return redirect('edit_domain', domain.name)
    else:
        f = None
    return render_to_response('manager/add_domain.html', {'key_types': TSIG_KEY_TYPES, 'domain': f},
                              context_instance=RequestContext(request))


@login_required
def edit_dyndns(request, id):
    try:
        client = Client.objects.get(pk=int(id), domain__users__pk=request.user.pk)
    except Client.DoesNotExist:
        raise Http404
    if request.method == 'POST':
        f = ClientEditForm(request.POST, instance=client)
        if f.is_valid():
            client = f.save()
            messages.success(request, "Details updated!")
        else:
            messages.error(request, "Failed to update details")
    return render_to_response('manager/edit_dyndns.html', {'client': client},
                              context_instance=RequestContext(request))


@login_required
def edit_dyndns_secret(request, id):
    try:
        client = Client.objects.get(pk=int(id), domain__users__pk=request.user.pk)
    except Client.DoesNotExist:
        raise Http404
    new_secret = gen_password(32)
    client.secret = new_secret
    client.save()
    url = "http"
    if request.is_secure():
        url += "s"

    url += "://%s%s" % (request.get_host(), reverse('api_update', args=(new_secret,)))
    return render_to_response('manager/edit_dyndns.html', {'client': client, 'secret': new_secret, 'update_url': url},
                              context_instance=RequestContext(request))


@login_required
def add_dyndns(request, name):
    try:
        domain = Domain.objects.get(name=name, users__pk=request.user.pk)
    except Domain.DoesNotExist:
        raise Http404
    form = None
    if request.method == 'POST':
        secret = gen_password(32)
        instance = Client(domain=domain, secret=secret)
        form = ClientForm(request.POST, instance=instance, initial={'domain': domain.pk, 'secret': secret})
        if form.is_valid():

            # Test unique

            if len(Client.objects.filter(domain=domain, name=form.cleaned_data['name']).all()) != 0:
                messages.error(request, "Client with same name already added!")

            else:
                client = form.save()
                url = "http"
                if request.is_secure():
                    url += "s"
                url += "://%s%s" % (request.get_host(), reverse('api_update', args=(secret,)))
                return render_to_response('manager/edit_dyndns.html', {'client': client,
                                                                   'secret': secret,
                                                                   'update_url': url},
                              context_instance=RequestContext(request))
    return render_to_response('manager/add_dyndns.html', {'domain': domain, 'client': form},
                              context_instance=RequestContext(request))


def update(request, secret):
    """
    Update dns record.

    TODO:
    - query ttl
    - query records from master instead of nearest resolver
    """
    pw_hash = hash_password(secret)
    client_ip = request.META['REMOTE_ADDR']
    client_type = 'A'
    if ':' in client_ip:
        client_type = 'AAAA'
    try:
        client = Client.objects.get(secret=pw_hash)
    except Client.DoesNotExist:
        return JsonResponse({'status': 'ERROR', 'msg':'Invalid secret'})
    logging.info("Updating %s to %s" % (client.fqdn, client_ip))
    try:
        if client_type == 'A':
            for address in dnsutils.get_ipv4(client.fqdn):
                dnsutils.doUpdate(client.domain.master, client.domain.tsig_key,
                                  client.domain.tsig_type, client.domain.fqdn,
                                  False, 'delete', '60', client_type, client.fqdn, address)
        else:
            for address in dnsutils.get_ipv6(client.fqdn):
                dnsutils.doUpdate(client.domain.master, client.domain.tsig_key,
                                  client.domain.tsig_type, client.domain.fqdn,
                                  False, 'delete', '60', client_type, client.fqdn, address)
    except Exception as e:
        logger.exception(e)
        return JsonResponse({'status': 'ERROR', 'msg':'Internal error'})
    try:
        if type == 'A':
            dnsutils.doUpdate(client.domain.master, client.domain.tsig_key,
                              client.domain.tsig_type, client.domain.fqdn, False,
                              'update', '60', client_type, client.fqdn, client_ip)
        else:
            dnsutils.doUpdate(client.domain.master, client.domain.tsig_key, client.domain.tsig_type,
                              client.domain.fqdn, False, 'update', '60', client_type, client.fqdn, client_ip)
    except Exception as e:
        logger.exception(e)
        return JsonResponse({'status': 'ERROR', 'msg':'Internal error'})
    return JsonResponse({'status': 'OK', 'msg': 'Successfully updated %s address to %s' % (client.fqdn, client_ip)})