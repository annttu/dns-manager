import string
from hashlib import sha512
import random


def hash_password(password, salt=None):
    if salt:
        password = password + salt
    return '$1$' + sha512(password.encode("utf-8")).hexdigest()

def gen_password(length=32):
    return ''.join([random.choice(string.ascii_letters + string.digits) for x in range(length)])