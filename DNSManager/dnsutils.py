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
import dns.zone
import socket
from dns.exception import DNSException, SyntaxError


import logging

logger = logging.getLogger('dns')


class DynDNSException(Exception):
    """
        Pass-through all self made errors
    """
    pass


class DNSRecordException(Exception):
    pass

keyTypes = {
    'HMAC_MD5': dns.tsig.HMAC_MD5,
    'HMAC_SHA1': dns.tsig.HMAC_SHA1,
    'HMAC_SHA224': dns.tsig.HMAC_SHA224,
    'HMAC_SHA256': dns.tsig.HMAC_SHA256,
    'HMAC_SHA384': dns.tsig.HMAC_SHA384,
    'HMAC_SHA512': dns.tsig.HMAC_SHA512
}

DNS_RECORD_TYPES = [
    'A',
    'AAAA',
    'SOA',
    'MX',
    'PTR',
    'SRV',
    'TXT',
    'NS',
    'CNAME',
    'SSHFP'
]

DNS_RECORD_TYPES_WITH_PTR = [
    'A',
    'AAAA'
]

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
        raise DynDNSException('Error: %s is not a valid name' % Name)
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
    if Type in DNS_RECORD_TYPES_WITH_PTR:
        myPayload = target
        if doPTR == True:
            ptrTarget = Name.to_text() + '.' + Origin.to_text()
            ptrOrigin, ptrName = parseName(None, genPTR(myPayload).to_text())
            ptrUpdate = dns.update.Update(ptrOrigin, keyring=KeyRing, keyalgorithm=keyAlgorithm)
    elif Type in DNS_RECORD_TYPES:
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


def axfr(Server, key, keyAlgorithm, Origin):
    """
    :param Server: DNS-server
    :param key: TSIG key
    :param keyAlgorithm: TSIG key algorithm
    :param Origin: domain
    :return: List of dns-records
    """
    KeyRing = checkKey(key)
    keyAlgorithm = getAlgorithm(keyAlgorithm)
    zone = dns.zone.from_xfr(dns.query.xfr(Server, Origin, keyring=KeyRing, keyalgorithm=keyAlgorithm))
    return zone


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
        responses = r.query(qname=key, rdtype=type)
        out = []
        if responses is not None:
            for response in responses:
               out.append(response.to_text())
        return out
    except DNSException:
        return []


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True


def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def validate_data(type, data, name):
    if type == 'A':
        if is_valid_ipv4_address(data):
            return
        raise DNSRecordException("Invalid ip-address for A record")

    elif type == 'AAAA':
        if is_valid_ipv6_address(data):
            return
        raise DNSRecordException("Invalid ipv6-address for AAAA record")

    elif type == 'NS':
        if len(data) > 2 and '.' in data and data.endswith('.'):
            return True
        raise DNSRecordException("Invalid DNS-server for NS record, syntax \"ns.example.com.\"")

    elif type == 'CNAME':
        if name != '':
            raise DNSRecordException("CNAME record cannot be added for empty name.")
        if len(data) > 2:
            return True
        raise DNSRecordException("Invalid DNS-server for CNAME record, syntax \"record.example.com.\" or \"record\"")

    elif type == 'TXT':
        if len(data.strip()) == 0:
            raise DNSRecordException("TXT record text cannot be empty!")
        elif len(data.strip()) > 255:
            raise DNSRecordException("TXT record text cannot be longer than 255 characters!")
        return True

    elif type == 'MX':
        if len(data.split()) != 2:
            raise DNSRecordException("MX record must contain priority and server, syntax \"5 mail.example.com.\"")
        priority, server = data.split()
        try:
            priority = int(priority)
        except ValueError:
            raise DNSRecordException("MX record must have valid priority, syntax \"5 mail.example.com.\"")

        if priority < 0 or priority > 255:
            raise DNSRecordException("MX record must have valid priority integer between 0 and 255," +
                                     "syntax \"5 mail.example.com.\"")
        try:
            int(server)
            raise DNSRecordException("MX record must have valid server string, syntax \"5 mail.example.com.\"")
        except ValueError:
            pass
        if len(server) < 2:
            raise DNSRecordException("MX record must have valid server with at least two characters, " +
                                     "syntax \"5 mail.example.com.\"")

        return True

    elif type == 'SSHFP':
        # http://www.iana.org/assignments/dns-sshfp-rr-parameters/dns-sshfp-rr-parameters.xml
        if len(data.split()) < 3:
            raise DNSRecordException("SSHFP record must contain algorithm, fingerprint type and fingerprint, " +
                                     "syntax \"2 1 0043570DB4CA50FD69FCF7775033440452AC470B\"")
        (algorithm, fingerprint_type, fingerprint) = data.split(None,2)
        items = {'algorithm': algorithm, 'fingerprint type': fingerprint_type}
        for k, v in items.items():
            try:
                v = int(v)
            except ValueError:
                raise DNSRecordException("SSHFP record %s must be positive integer between 0 and 255." % k)
            if v < 0 or v > 255:
                raise DNSRecordException("SSHFP record %s must be positive integer between 0 and 255." % k)
        if len(fingerprint) < 2:
            raise DNSRecordException("SSHFP record must have valid base64 encoded fingerprint.")
        return True

    elif type == 'SRV':
        if len(data.split()) != 4:
            raise DNSRecordException("SRV record must contain priority, weight, port and server, " +
                                     "syntax \"5 0 5222 jabber.example.com.\"")
        (priority, weight, port, server) = data.split()
        items = {'priority': priority, 'weight': weight, 'port': port}
        for k, v in items.items():
            try:
                v = int(v)
            except ValueError:
                raise DNSRecordException("SRV record %s must be positive integer between 0 and 65535." % k)
            if v < 0 or v > 65535:
                raise DNSRecordException("SRV record %s must be positive integer between 0 and 65535." % k)
        if len(server) < 2:
            raise DNSRecordException("SRV record server must be valid DNS name.")
        return True

    elif type == 'SOA':
        if name != '':
            raise DNSRecordException("SOA record can be added only for empty name")
        parts = data.split()
        if len(parts) != 7:
            return False
        (ns, hostmaster, serial, refresh, retry, expiry, negative_ttl) = data.split(None, 6)

        if len(ns) < 2 or '.' not in  ns or not ns.endswith('.'):
            raise DNSRecordException("SOA record should have valid dns-server field.")

        # email-address
        if len(hostmaster.split('.')) < 2:
            raise DNSRecordException("Invalid hostmaster address for SOA record, syntax is \"hostmaster.domain.tld.\"")
        if not hostmaster.endswith('.'):
            raise DNSRecordException("Hostmaster address should end with dot.")

        # Serial
        try:
            serial = int(serial)
        except ValueError:
            raise DNSRecordException("Invalid serial %s value in SOA record" % serial)
        if serial > 4294967295:
            raise DNSRecordException("Serial %s value too big for SOA record, upper limit 4294967295" % serial)
        if serial < 1:
            raise DNSRecordException("Serial %s value too small for SOA record, lower limit 1" % serial)

        numbers = {
            'refresh': refresh,
            'retry': retry,
            'expiry': expiry,
            'negative ttl': negative_ttl
        }

        for k, v in numbers.items():
            try:
                v = int(v)
            except ValueError:
                raise DNSRecordException("Invalid %s %s value in SOA record" % (k, v))
            if v > 4294967295:
                raise DNSRecordException("%s %s value too big for SOA record, upper limit 4294967295" % (k, v))
            if v < 1:
                raise DNSRecordException("%s %s value too small for SOA record, lower limit 1" % (k, v))

    else:
        raise DNSRecordException("Unsupported record type %s" % type)