import string
from hashlib import sha512
import random


def hash_password(password, salt=None):
    if salt:
        password = password + salt
    return '$1$' + sha512(password.encode("utf-8")).hexdigest()

def gen_password(length=32):
    return ''.join([random.choice(string.ascii_letters + string.digits) for x in range(length)])

def strtobool(val):
    if isinstance(val, bool):
        return val
    elif isinstance(val, str):
        val = val.lower()
        if val in ('y', 'yes', 't', 'true', 'on', '1'):
            return True
        elif val in ('n', 'no', 'f', 'false', 'off', '0'):
            return False
    raise ValueError("invalid truth value %r" % (val,))