from hashlib import sha512


def hash_password(password, salt=None):
    if salt:
        password = password + salt
    return '$1$' + sha512(password.encode("utf-8")).hexdigest()