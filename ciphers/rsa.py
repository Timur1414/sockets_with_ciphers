from math import gcd
from Crypto.Util.number import getPrime

class RSA:
    BIT_LENGTH = 128

    @staticmethod
    def __gcd_extended(a, b):
        if a == 0:
            return b, 0, 1
        else:
            div, x, y = RSA.__gcd_extended(b % a, a)
        return div, y - (b // a) * x, x

    @staticmethod
    def generate_keys():
        p = getPrime(RSA.BIT_LENGTH)
        q = getPrime(RSA.BIT_LENGTH)
        n = p * q
        f = (p - 1) * (q - 1)
        e = 2
        while gcd(e, f) != 1:
            e += 1
        div, x, y = RSA.__gcd_extended(e, f)
        d = x % f
        print(f'Open key: ({e}, {n})')
        print(f'Close key: ({d}, {n})')
        return (e, n), (d, n)

    @staticmethod
    def encrypt(message, open_key):
        encrypted_message = pow(message, open_key[0], open_key[1])
        return encrypted_message

    @staticmethod
    def decrypt(message, close_key):
        decrypted_message = pow(message, close_key[0], close_key[1])
        return decrypted_message
