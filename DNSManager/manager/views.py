from datetime import datetime, timedelta
from django.contrib import messages
from django.contrib.auth import logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import login
from django.core.urlresolvers import reverse
from django.shortcuts import render_to_response, redirect
from django.template import RequestContext
from django.http import JsonResponse, HttpResponseRedirect, Http404, HttpRequest, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.parsers import JSONParser
from rest_framework.renderers import JSONRenderer
from rest_framework.views import APIView
from rest_framework import permissions

from manager.serializers import DomainSerializer, DNSEntryCacheSerializer
from .models import Client, Domain, TSIG_KEY_TYPES, DNSEntryCache
from .forms import *
from utils import hash_password, gen_password
from django.db import transaction
import socket
from dns.exception import DNSException
import logging
import dnsutils


logger = logging.getLogger('manager.views')


def login_page(request):
    logout(request)
    username = password = ''
    if request.POST:
        username = request.POST['username']
        password = request.POST['password']
        remember = None
        if 'remember' in request.POST:
            remember = request.POST['remember']

        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                if remember:
                    request.session.set_expiry(0)
                return HttpResponseRedirect('/')
    return render_to_response('manager/login.html',
                              context_instance=RequestContext(request))


def get_domain_records(request, domain):
    try:
        synchronize(domain)
    except:
        if isinstance(request, HttpRequest):
            messages.error(request, "Cannot refresh dns-entries from server")

    entries = []

    for entry in DNSEntryCache.user_objects(request.user).filter(domain=domain).all():
        try:
            domain.client_set.get(name=entry.name)
        except Client.DoesNotExist:
            entries.append(entry)
    return entries


@login_required(login_url='/login')
def index(request):
    domains = Domain.user_objects(request.user).all()
    return render_to_response('manager/index.html', {'domains': domains},
                              context_instance=RequestContext(request))

@login_required
def edit_domain(request, name):

    try:
        domain = Domain.user_objects(request.user).get(name=name)
    except Domain.DoesNotExist:
        raise Http404

    if request.method == 'POST':
        name = str(domain.name)
        f = DomainEditForm(request.POST, instance=domain)
        if f.is_valid():
            if name != f.cleaned_data['name']:
                messages.error(request, "Name cannot be changed!")
            else:
                domain = f.save()
                messages.success(request, "Successfully update domain %s details" % (f.cleaned_data['name']))
                return redirect('show_domain', domain.name)
    else:
        f = None

    return render_to_response('manager/edit_domain.html', {'domain': domain, 'form': f,
                                                           'key_types': TSIG_KEY_TYPES},
                              context_instance=RequestContext(request))

@login_required
def show_domain(request, name):
    try:
        domain = Domain.user_objects(request.user).get(name=name)
    except Domain.DoesNotExist:
        raise Http404

    entries = get_domain_records(request, domain)
    return render_to_response('manager/show_domain.html', {'domain': domain, 'static_entries': entries},
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
            return redirect('show_domain', domain.name)
    else:
        f = None
    return render_to_response('manager/add_domain.html', {'key_types': TSIG_KEY_TYPES, 'domain': f},
                              context_instance=RequestContext(request))


@login_required
def edit_dyndns(request, id):
    try:
        client = Client.user_objects(request.user).get(pk=int(id))
    except Client.DoesNotExist:
        raise Http404
    if request.method == 'POST':
        f = ClientEditForm(request.POST, instance=client)
        if f.is_valid():
            client = f.save()
            messages.success(request, "Details updated!")
        else:
            messages.error(request, "Failed to update details")

    # Fetch and show also associated entries
    try:
        synchronize(client.domain, True)
        messages.success(request, "Successfully updated cache")
    except:
        messages.error(request, "Cannot refresh dns-entries from server")


    records = []

    for entry in DNSEntryCache.user_objects(request.user).filter(domain=client.domain).all():
        if entry.name == client.name:
            records.append(entry)

    return render_to_response('manager/edit_dyndns.html', {'domain': client.domain, 'client': client, 'records': records},
                              context_instance=RequestContext(request))


@login_required
def edit_dyndns_secret(request, id):
    try:
        client = Client.user_objects(request.user).get(pk=int(id))
    except Client.DoesNotExist:
        raise Http404
    new_secret = gen_password(32)
    client.secret = new_secret
    client.save()
    url = "http"
    if request.is_secure():
        url += "s"
    url += "://%s%s" % (request.get_host(), reverse('api_update', args=(new_secret,)))

    # Fetch and show also associated entries
    try:
        synchronize(client.domain, True)
        messages.success(request, "Successfully updated cache")
    except:
        messages.error(request, "Cannot refresh dns-entries from server")

    records = []

    for entry in DNSEntryCache.user_objects(request.user).filter(domain=client.domain).all():
        if entry.name == client.name:
            records.append(entry)

    return render_to_response('manager/edit_dyndns.html', {'domain': client.domain, 'client': client, 'records': records, 'secret': new_secret, 'update_url': url},
                              context_instance=RequestContext(request))


@login_required
def add_dyndns(request, name):
    try:
        domain = Domain.user_objects(request.user).get(name=name)
    except Domain.DoesNotExist:
        raise Http404
    form = None
    if request.method == 'POST':
        secret = gen_password(32)
        instance = Client(domain=domain, secret=secret)
        form = ClientForm(request.POST, instance=instance, initial={'domain': domain.pk, 'secret': secret})
        if form.is_valid():

            # Test unique

            if len(Client.user_objects(request.user).filter(domain=domain, name=form.cleaned_data['name']).all()) != 0:
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


@login_required
def delete_dyndns(request, id):
    try:
        client = Client.user_objects(request.user).get(pk=int(id))
    except Client.DoesNotExist:
        raise Http404
    form = None
    if request.method == 'POST':
        form = ConfirmDeleteForm(request.POST)
        if form.is_valid():
            delete_client(client)
            client.delete()
            return redirect('show_domain', client.domain.name)
    return render_to_response('manager/delete_dyndns.html', {'client': client, 'form': form},
                              context_instance=RequestContext(request))



@login_required
def synchronize_domain(request, domain):
    try:
        domain = Domain.user_objects(request.user).get(name=domain)
    except Domain.DoesNotExist:
        raise Http404

    try:
        synchronize(domain, True)
        messages.success(request, "Successfully updated cache")
    except:
        messages.error(request, "Cannot refresh dns-entries from server")


    return redirect('show_domain', domain.name)


@login_required
def synchronize_dyndns(request, id):
    try:
        client = Client.user_objects(request.user).get(pk=int(id))
    except Client.DoesNotExist:
        raise Http404

    try:
        synchronize(client.domain, True)
        messages.success(request, "Successfully updated cache")
    except:
        messages.error(request, "Cannot refresh dns-entries from server")

    return redirect('edit_dyndns', client.pk)


@login_required
def add_static(request, domain):
    try:
        domain = Domain.user_objects(request.user).get(name=domain)
    except Domain.DoesNotExist:
        raise Http404

    try:
        synchronize(domain)
    except:
        messages.error(request, "Cannot refresh dns-entries from server")

    form = None

    response_data = {
        'dns_record_types': dnsutils.DNS_RECORD_TYPES,
        'domain': domain,
        'form': form
    }

    if request.method == 'POST':
        instance = DNSEntryCache()
        instance.domain = domain
        form = StaticEntryForm(request.POST, initial={'name': ''}, instance=instance)
        if form.is_valid():
            response_data['form'] = form
            try:
                dnsutils.validate_data(form.cleaned_data['type'].strip(), form.cleaned_data['data'].strip(),
                                       form.cleaned_data['name'].strip())
            except dnsutils.DNSRecordException as e:
                messages.error(request, str(e))
                return render_to_response('manager/add_static.html', response_data,
                                          context_instance=RequestContext(request))

            # Save data
            entry = form.save()

            # Add record also to dns-server
            dnsutils.doUpdate(domain.master, domain.tsig_key, domain.tsig_type, domain.name, False,
                              'add', str(form.cleaned_data['ttl']), form.cleaned_data['type'],
                              entry.fqdn, form.cleaned_data['data'])

            messages.success(request, "Successfully added entry %s %s %s %s" % (
                             entry.fqdn, entry.ttl, entry.type, entry.data))

            return redirect('show_domain', domain.name)

    return render_to_response('manager/add_static.html', response_data,
                              context_instance=RequestContext(request))


@login_required
def edit_static(request, domain, entry):
    if domain.endswith('.'):
        domain = domain[:-1]

    try:
        domain = Domain.user_objects(request.user).get(name=domain)
    except Domain.DoesNotExist:
        raise Http404

    #synchronize(domain)

    try:
        instance = DNSEntryCache.user_objects(request.user).get(pk=int(entry))
        old_instance = DNSEntryCache.user_objects(request.user).get(pk=int(entry))
    except DNSEntryCache.DoesNotExist:
        raise Http404

    name = str(instance.name)

    response_data = {
        'dns_record_types': dnsutils.DNS_RECORD_TYPES,
        'instance': instance,
        'domain': domain,
        'form': None
    }

    if request.method == 'POST':
        form = StaticEntryEditForm(request.POST, initial={'name': ''}, instance=instance)
        if form.is_valid():

            response_data['form'] = form
            if form.cleaned_data['name'] != name:
                messages.error(request, "To change entry name, delete old record and add a new one.")
                return render_to_response('manager/add_static.html', response_data,
                                          context_instance=RequestContext(request))

            try:
                dnsutils.validate_data(form.cleaned_data['type'], form.cleaned_data['data'],
                                       form.cleaned_data['name'])
            except dnsutils.DNSRecordException as e:
                messages.error(request, str(e))
                return render_to_response('manager/add_static.html', response_data,
                                          context_instance=RequestContext(request))

            entry = form.save()

            # Add to real dns

            try:
                dnsutils.doUpdate(domain.master, domain.tsig_key, domain.tsig_type, domain.name, False,
                              'delete', str(old_instance.ttl), old_instance.type,
                              old_instance.fqdn, old_instance.data)
                dnsutils.doUpdate(domain.master, domain.tsig_key, domain.tsig_type, domain.name, False,
                              'add', str(form.cleaned_data['ttl']), form.cleaned_data['type'],
                              entry.fqdn, form.cleaned_data['data'])
                messages.success(request, "Successfully updated entry %s %s %s %s" % (
                             entry.fqdn, entry.ttl, entry.type, entry.data))

            except Exception:
                messages.error(request, "Cannot update values to DNS-server.")
                transaction.rollback()


            return redirect('show_domain', domain.name)

    else:
        response_data['form'] = StaticEntryForm(instance=instance)

    return render_to_response('manager/add_static.html', response_data,
                              context_instance=RequestContext(request))


@login_required
def delete_static(request, domain, entry):
    if domain.endswith('.'):
        domain = domain[:-1]

    try:
        domain = Domain.user_objects(request.user).get(name=domain)
    except Domain.DoesNotExist:
        raise Http404

    try:
        instance = DNSEntryCache.user_objects(request.user).get(pk=int(entry))
    except DNSEntryCache.DoesNotExist:
        raise Http404

    form = None

    if request.method == 'POST':
        form = ConfirmDeleteForm(request.POST)
        print(form['confirmed'])
        if form.is_valid():
            dnsutils.doUpdate(domain.master, domain.tsig_key, domain.tsig_type, domain.name, False,
                              'delete', str(instance.ttl), instance.type,
                              instance.fqdn, instance.data)
            instance.delete()
            messages.success(request, "Successfully deleted entry %s %s %s %s" % (
                             instance.fqdn, instance.ttl, instance.type, instance.data))
            return redirect('show_domain', domain.name)
    return render_to_response('manager/delete_static.html', {'domain': domain, 'entry': instance, 'form': form},
                              context_instance=RequestContext(request))


def synchronize(domain, force=False):
    """
    Synchronize domain dns-entries to database.
    Synchronize only if more than 60 seconds from previous.
    :param domain: Domain object
    :return: None
    """

    if not force:
        try:
            DNSEntryCache.objects.get(domain=domain, timestamp__gt=(datetime.now() - timedelta(seconds=60)))
            return
        except DNSEntryCache.DoesNotExist:
            pass
        except DNSEntryCache.MultipleObjectsReturned:
            pass

    zone = dnsutils.axfr(domain.master, domain.tsig_key,
                         domain.tsig_type, domain.fqdn)

    for entry in DNSEntryCache.objects.filter(domain=domain).all():
        entry.delete()

    for name, rdataset in zone.iterate_rdatasets():
        name = name.to_text()
        # There is maybe better way to do it, but dnspython is complex...
        # 60 IN A 88.113.97.101
        for line in rdataset.to_text().splitlines():
            (ttl, rclass, rtype, rdata) = line.split(None, 3)
            # Skip dnssec records for now.
            if rtype in ['RRSIG', 'TYPE65534', 'DNSKEY', 'NSEC']:
                continue
            entry = DNSEntryCache()
            if name != "@":
                entry.name = name
            else:
                entry.name = ""
            entry.domain = domain
            entry.ttl = int(ttl)
            entry.record_class = rclass.strip()
            entry.type = rtype.strip()
            entry.data = rdata.strip()
            entry.save()


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
        for address in dnsutils.do_resolve(client.fqdn, client_type, client.domain.master):
            dnsutils.doUpdate(client.domain.master, client.domain.tsig_key,
                                  client.domain.tsig_type, client.domain.fqdn,
                                  False, 'delete', '60', client_type, client.fqdn, address)
    except Exception as e:
        logger.exception(e)
        return JsonResponse({'status': 'ERROR', 'msg':'Internal error'})
    try:
        dnsutils.doUpdate(client.domain.master, client.domain.tsig_key,
                          client.domain.tsig_type, client.domain.fqdn, False,
                          'update', '60', client_type, client.fqdn, client_ip)
    except Exception as e:
        logger.exception(e)
        return JsonResponse({'status': 'ERROR', 'msg':'Internal error'})
    return JsonResponse({'status': 'OK', 'msg': 'Successfully updated %s address to %s' % (client.fqdn, client_ip)})


def delete_client(client):
    """
    Delete dyndns client
    :param request:
    :param client:
    :return:
    """
    synchronize(client.domain)

    for entry in DNSEntryCache.objects.filter(domain=client.domain, name=client.name).all():

        dnsutils.doUpdate(entry.domain.master, entry.domain.tsig_key,
                                  client.domain.tsig_type, entry.domain.fqdn,
                                  False, 'delete', str(entry.ttl), entry.type, entry.fqdn, entry.data)
        entry.delete()


@login_required
def password_changed(request):
    messages.success(request, "Password successfully changed!")
    return redirect("index")
    #return index(request)


# Rest stuff


class JSONResponse(HttpResponse):
    """
    An HttpResponse that renders its content into JSON.
    """
    def __init__(self, data, **kwargs):
        content = JSONRenderer().render(data)
        kwargs['content_type'] = 'application/json'
        super(JSONResponse, self).__init__(content, **kwargs)


class DomainList(APIView):

    def get(self, request, format=None):
        domains = Domain.user_objects(self.request.user).all()
        serializer = DomainSerializer(domains, many=True)
        return JSONResponse(serializer.data)

    def post(self, request, format=None):
        data = JSONParser().parse(request)
        serializer = DomainSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return JSONResponse(serializer.data, status=status.HTTP_201_CREATED)
        return JSONResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def perform_create(self, serializer):
        serializer.save(users=[self.request.user])


class DomainDetail(APIView):
    """
    Retrieve, update or delete a domain.
    """

    def get_object(self, pk):
        try:
            return Domain.user_objects(self.request.user).get(pk=pk)
        except Domain.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        domain = self.get_object(pk)
        serializer = DomainSerializer(domain)
        return JSONResponse(serializer.data)

    def put(self, request, pk, format=None):
        domain = self.get_object(pk)
        data = JSONParser().parse(request)
        serializer = DomainSerializer(domain, data=data)
        if serializer.is_valid():
            serializer.save()
            return JSONResponse(serializer.data)
        return JSONResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        domain = self.get_object(pk)
        domain.delete()
        return HttpResponse(status=status.HTTP_204_NO_CONTENT)


class RecordList(APIView):

    def get_domain(self, domain_id):
        try:
            return Domain.user_objects(self.request.user).get(pk=domain_id)
        except Domain.DoesNotExist:
            raise Http404

    def get(self, request, domain_id, format=None):
        domain = self.get_domain(domain_id)
        synchronize(domain)
        records = get_domain_records(request, domain)
        serializer = DNSEntryCacheSerializer(records, many=True)
        return JSONResponse(serializer.data)

    def post(self, request, domain_id, format=None):
        domain = self.get_domain(domain_id)
        data = JSONParser().parse(request)
        serializer = DNSEntryCacheSerializer(data=data)
        if serializer.is_valid():
            record = serializer.save(domain=domain)
            dnsutils.doUpdate(domain.master, domain.tsig_key, domain.tsig_type,
                          domain.name, False, 'add', str(record.ttl),
                          record.type, record.fqdn, record.data)
            return JSONResponse(serializer.data, status=status.HTTP_201_CREATED)
        return JSONResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RecordDetail(APIView):
    """
    Retrieve, update or delete a record.
    """

    def get_object(self, domain_id, pk):
        domain = self.get_domain(domain_id)
        synchronize(domain)
        try:
            return DNSEntryCache.user_objects(self.request.user).get(pk=pk, domain=domain)
        except DNSEntryCache.DoesNotExist:
            raise Http404

    def get_domain(self, domain_id):
        try:
            return Domain.user_objects(self.request.user).get(pk=domain_id)
        except Domain.DoesNotExist:
            raise Http404

    def get(self, request, domain_id, pk, format=None):
        record = self.get_object(domain_id, pk)
        serializer = DNSEntryCacheSerializer(record)
        return JSONResponse(serializer.data)

    def put(self, request, domain_id, pk, format=None):
        record = self.get_object(domain_id, pk)
        data = JSONParser().parse(request)
        serializer = DNSEntryCacheSerializer(record, data=data)
        if serializer.is_valid():
            new_instance = serializer.save()

            dnsutils.doUpdate(record.domain.master, record.domain.tsig_key, record.domain.tsig_type,
                              record.domain.name, False, 'delete', str(record.ttl), record.type,
                              record.fqdn, record.data)
            dnsutils.doUpdate(new_instance.domain.master, new_instance.domain.tsig_key, new_instance.domain.tsig_type,
                              new_instance.domain.name, False, 'add', str(new_instance.ttl),
                              new_instance.type, new_instance.fqdn, new_instance.data)

            return JSONResponse(serializer.data)
        return JSONResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, domain_id, pk, format=None):
        record = self.get_object(domain_id, pk)

        dnsutils.doUpdate(record.domain.master, record.domain.tsig_key, record.domain.tsig_type,
                          record.domain.name, False, 'delete', str(record.ttl), record.type,
                          record.fqdn, record.data)

        record.delete()

        return HttpResponse(status=status.HTTP_204_NO_CONTENT)
