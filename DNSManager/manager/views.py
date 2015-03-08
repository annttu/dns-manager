from django.shortcuts import render_to_response
from django.template import RequestContext
from django.http import JsonResponse
from .models import Client, Domain
from utils import hash_password
import socket
import logging
import dnsutils

logger = logging.getLogger('manager.views')


def index(request):
    return render_to_response('manager/index.html', {}, content_type=RequestContext(request))


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
                dnsutils.doUpdate(client.domain.master, client.domain.tsig_key, client.domain.tsig_type, client.domain.fqdn, False, 'delete', '60', client_type, client.fqdn, address)
        else:
            for address in dnsutils.get_ipv6(client.fqdn):
                dnsutils.doUpdate(client.domain.master, client.domain.tsig_key, client.domain.tsig_type, client.domain.fqdn, False, 'delete', '60', client_type, client.fqdn, address)
    except Exception as e:
        logger.exception(e)
        return JsonResponse({'status': 'ERROR', 'msg':'Internal error'})
    try:
        if type == 'A':
            dnsutils.doUpdate(client.domain.master, client.domain.tsig_key, client.domain.tsig_type, client.domain.fqdn, False, 'update', '60', client_type, client.fqdn, client_ip)
        else:
            dnsutils.doUpdate(client.domain.master, client.domain.tsig_key, client.domain.tsig_type, client.domain.fqdn, False, 'update', '60', client_type, client.fqdn, client_ip)
    except Exception as e:
        logger.exception(e)
        return JsonResponse({'status': 'ERROR', 'msg':'Internal error'})
    return JsonResponse({'status': 'OK', 'msg': 'Successfully updated %s address to %s' % (client.fqdn, client_ip)})