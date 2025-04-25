from math import gcd
from Crypto.Util.number import getPrime


def gcd_extended(num1, num2):
    if num1 == 0:
        return num2, 0, 1
    else:
        div, x, y = gcd_extended(num2 % num1, num1)
    return div, y - (num2 // num1) * x, x


def generate_keys():
    bit_length = 128
    p = getPrime(bit_length)
    q = getPrime(bit_length)
    n = p * q
    f = (p - 1) * (q - 1)
    e = 2
    while gcd(e, f) != 1:
        e += 1
    div, x, y = gcd_extended(e, f)
    d = x % f
    print(f'Open key: ({e}, {n})')
    print(f'Close key: ({d}, {n})')
    return (e, n), (d, n)


def encrypt(message, open_key):
    encrypted_message = pow(message, open_key[0], open_key[1])
    return encrypted_message


def decrypt(encrypted_message, close_key):
    decrypted_message = pow(encrypted_message, close_key[0], close_key[1])
    return decrypted_message
