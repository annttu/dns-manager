# encoding: utf-8

"""
DNS library for dyndns script

This file is modified version of
http://planetfoo.org/files/dnsupdate.py
"""

import dns.query
import dns.tsigkeyring
import dns.update
import dns.reversename
import dns.resolver
import dns.edns
import socket
from dns.exception import DNSException, SyntaxError


import logging

logger = logging.getLogger('dns')


class DynDNSException(Exception):
    """
        Pass-through all self made errors
    """
    pass


keyTypes = {
    'HMAC_MD5': dns.tsig.HMAC_MD5,
    'HMAC_SHA1': dns.tsig.HMAC_SHA1,
    'HMAC_SHA224': dns.tsig.HMAC_SHA224,
    'HMAC_SHA256': dns.tsig.HMAC_SHA256,
    'HMAC_SHA384': dns.tsig.HMAC_SHA384,
    'HMAC_SHA512': dns.tsig.HMAC_SHA512
}


def checkKey(key):
    try:
        k = {key.rsplit(' ')[0]:key.rsplit(' ')[6]}
    except IndexError:
        raise DynDNSException('%s is not a valid key. The file should be in DNS KEY record format. See dnssec-keygen(8)' % k)
    try:
        KeyRing = dns.tsigkeyring.from_text(k)
    except:
        raise DynDNSException('%s is not a valid key. The file should be in DNS KEY record format. See dnssec-keygen(8)' % k)
    return KeyRing


def getAlgorithm(keyType):
    return keyTypes[keyType]


def genPTR(Address):
    try:
        a = dns.reversename.from_address(Address)
    except:
        raise DynDNSException('Error: %s is not a valid IP address' % Address)
    return a


def parseName(Origin, Name):
    try:
        n = dns.name.from_text(Name)
    except:
        DynDNSException('Error: %s is not a valid name' % n)
    if Origin is None:
        Origin = dns.resolver.zone_for_name(n)
        Name = n.relativize(Origin)
        return Origin, Name
    else:
        try:
            Origin = dns.name.from_text(Origin)
        except:
            raise DynDNSException('Error: %s is not a valid origin' % Name)
        Name = n - Origin
        return Origin, Name


def doUpdate(Server, key, keyAlgorithm, Origin, doPTR, Action, TTL, Type, client, target):
    # Get the hostname and the origin
    TTL = dns.ttl.from_text(TTL)
    Origin, Name = parseName(Origin, client)
    # Validate and setup the Key
    KeyRing = checkKey(key)
    # Start constructing the DDNS Query

    keyAlgorithm = getAlgorithm(keyAlgorithm)

    Update = dns.update.Update(Origin, keyring=KeyRing, keyalgorithm=keyAlgorithm)
    # Put the payload together.
    if Type == 'A' or Type == 'AAAA':
        myPayload = target
        if doPTR == True:
            ptrTarget = Name.to_text() + '.' + Origin.to_text()
            ptrOrigin, ptrName = parseName(None, genPTR(myPayload).to_text())
            ptrUpdate = dns.update.Update(ptrOrigin, keyring=KeyRing, keyalgorithm=keyAlgorithm)
    elif Type == 'CNAME' or Type == 'NS' or Type == 'TXT' or Type == 'PTR':
        myPayload = target
        do_PTR = False
    else:
        raise DynDNSException("Unknown type %s" % Type)
    # Build the update
    if Action == 'add':
        Update.add(Name, TTL, Type, myPayload)
        if doPTR == True:
            ptrUpdate.add(ptrName, TTL, 'PTR', ptrTarget)
    elif Action == 'delete' or Action == 'del':
        Update.delete(Name, Type, myPayload)
        if doPTR == True:
            ptrUpdate.delete(ptrName, 'PTR', ptrTarget)
    elif Action == 'update':
        Update.replace(Name, TTL, Type, myPayload)
        if doPTR == True:
            ptrUpdate.replace(ptrName, TTL, 'PTR', ptrTarget)
    # Do the update
    try:
        Response = dns.query.tcp(Update, Server)
    except dns.tsig.PeerBadKey:
        raise DynDNSException('ERROR: The server is refusing our key')
    logger.info('Creating %s record for %s resulted in: %s' % (Type, Name, dns.rcode.to_text(Response.rcode())))
    if dns.rcode.to_text(Response.rcode()) != 'NOERROR':
        raise DynDNSException('ERROR: Creating %s record for %s resulted in: %s' % (Type, Name, dns.rcode.to_text(Response.rcode())))
    if doPTR == True:
        try:
            ptrResponse = dns.query.tcp(ptrUpdate, Server)
        except dns.tsig.PeerBadKey:
            raise DynDNSException('ERROR: The server is refusing our key')
        logger.info('Creating PTR record for %s resulted in: %s' % (Name, dns.rcode.to_text(Response.rcode())))


def get_ipv4(address):
    try:
        res = socket.getaddrinfo(address, 80, socket.AF_INET)
    except socket.gaierror:
        return []
    out = []
    for x in res:
        if x[4][0] not in res:
            out.append(x[4][0])
    return out


def get_ipv6(address):
    try:
        res = socket.getaddrinfo(address, 80, socket.AF_INET6)
    except socket.gaierror:
        return []
    out = []
    for x in res:
        if x[4][0] not in res:
            out.append(x[4][0])
    return out


def do_resolve(key, type, server):
    server = get_ipv6(server) + get_ipv4(server)
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = server
        responses = r.query(qname=key, rdtype=type, raise_on_no_answer=False)
        out = []
        if responses:
            for response in responses:
               out.append(response.to_text())
        return out
    except DNSException:
        return []
