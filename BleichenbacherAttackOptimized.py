import intervals as I
import random
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
def pkcs1_v15_pad(buffer, modulus_size):
    prefix = b'\x00\x02'
    suffix = b'\x00'
    padding_size = modulus_size // 8 - len(prefix) - len(suffix) - len(buffer)
    if padding_size < 8:
        raise ValueError('message too long')
    padding = bytearray(random.choices(range(1, 256), k=padding_size))
    paddedMessage = prefix + padding + suffix + buffer
    return paddedMessage


def pkcs1_v15_unpad(buffer, modulus_size):
    buffer = buffer.rjust(modulus_size // 8, b'\x00')
    separator_index = buffer.find(b'\x00', 2)
    assert separator_index != -1 and separator_index + 1 < len(buffer)
    return buffer[(separator_index + 1):]


def encrypt(message, public_key):
    cipher_rsa = PKCS1_v1_5.new(public_key)
    ciphertext = cipher_rsa.encrypt(message)
    return ciphertext

def encryptWithoutBib(message, public_key):
    return long_to_bytes(pow(bytes_to_long(message), public_key.e, public_key.n))

def decryptWithoutBib(cipher, d, n):
    return pow(bytes_to_long(cipher), d, n)
def oracle(ciphertext, private_key):
    try:
        sentinel = "Error"
        cipher_rsa = PKCS1_v1_5.new(private_key)
        message = cipher_rsa.decrypt(ciphertext, sentinel)
        if message == "Error":
            return False
        else:
            return True
    except:
        return False

def oracleWithoutBib(ciphertext, private_key):
    message = decryptWithoutBib(ciphertext, private_key.d, private_key.n)
    bytes = long_to_bytes(message, 128)
    return bytes[:2] == b'\x00\x02'
def ceil(x, y):
    return x // y + (x % y > 0)


def floor(x, y):
    return x // y


def nextIntervalls(currentIntervalls, si, B, n):
    M_i = I.empty()
    for intervall in currentIntervalls:
        a = intervall.lower
        b = intervall.upper
        lowerR = ceil(a * si - 3 * B + 1, n)
        upperR = ceil(b * si - 2 * B, n)
        for r in range(lowerR, upperR):
            new_a = max(a, ceil(2 * B + r * n, si))
            new_b = min(b, floor(3 * B - 1 + r * n, si))
            if new_a <= new_b:
                M_new = I.closed(new_a, new_b)
                M_i = M_i | M_new
    return M_i


def bleichenbacherAttack(cipher, public_key, private_key):
    B = 2 ** (8 * 126)
    s0 = 1
    a = 2 * B
    b = 3 * B - 1
    M = I.closed(a, b)
    e = public_key.e
    n = public_key.n
    cipher = bytes_to_long(cipher)
    s = ceil(n, 3 * B)
    ci = long_to_bytes((cipher * pow(s, e, n)) % n)
    while not oracle(ci, private_key):
        s += 1
        ci = long_to_bytes((cipher * pow(s, e, n)) % n)
    M = nextIntervalls(M, s, B, n)

    while True:
        if len(M) > 1:
            s += 1
            ci = long_to_bytes((cipher * pow(s, e, n)) % n)
            while not oracle(ci, private_key):
                s += 1
                ci = long_to_bytes((cipher * pow(s, e, n)) % n)
        elif len(M) == 1 and M.lower == M.upper:
            break
        else:
            a = M.lower
            b = M.upper
            r = ceil((b * s - 2 * B) * 2, n)
            changed = False
            while not changed:
                lowerS = ceil(2 * B + r * n, b)
                upperS = ceil(3 * B + r * n, a)
                for si in range(lowerS, upperS):
                    ci = long_to_bytes((cipher * pow(si, e, n)) % n)
                    if oracle(ci, private_key):
                        changed = True
                        s = si
                r += 1
        M = nextIntervalls(M, s, B, n)
        print(M)
    a = M.lower
    m = a % n
    print(pkcs1_v15_unpad(long_to_bytes(m), 128))

def bleichenbacherAttackWithoutBib(cipher, public_key, private_key):
    B = 2 ** (8 * 126)
    a = 2 * B
    b = 3 * B - 1
    M = I.closed(a, b)
    e = public_key.e
    n = public_key.n
    queriesNeeded = 0
    cipher = bytes_to_long(cipher)
    intervalList = []
    intervalList.append(M)
    s = ceil(n, 3 * B)
    ci = long_to_bytes((cipher * pow(s, e, n)) % n)
    queriesNeeded += 1
    while not oracleWithoutBib(ci, private_key):
        s += 1
        queriesNeeded += 1
        ci = long_to_bytes((cipher * pow(s, e, n)) % n)
    M = nextIntervalls(M, s, B, n)
    print("End of phase 1")
    while True:
        if len(M) > 1:
            s += 1
            ci = long_to_bytes((cipher * pow(s, e, n)) % n)
            queriesNeeded += 1
            while not oracleWithoutBib(ci, private_key):
                s += 1
                queriesNeeded += 1
                ci = long_to_bytes((cipher * pow(s, e, n)) % n)
        elif len(M) == 1 and M.lower == M.upper:
            break
        else:
            a = M.lower
            b = M.upper
            r = ceil((b * s - 2 * B) * 2, n)
            changed = False
            while not changed:
                lowerS = ceil(2 * B + r * n, b)
                upperS = ceil(3 * B + r * n, a)
                for si in range(lowerS, upperS):
                    ci = long_to_bytes((cipher * pow(si, e, n)) % n)
                    queriesNeeded += 1
                    if oracleWithoutBib(ci, private_key):
                        changed = True
                        s = si
                r += 1
        M = nextIntervalls(M, s, B, n)
        intervalList.append(M)
    for intervall in intervalList[:10]:
        print(intervall)
    a = M.lower
    m = a % n
    print("Queries needed: ", queriesNeeded)
    print(pkcs1_v15_unpad(long_to_bytes(m), 128))

# Generiere ein RSA-Schlüsselpaar
key = RSA.generate(1024)
message = b'Never gonna give you up'
paddedMessage = pkcs1_v15_pad(message, 1024)
cipherPaddedMessage=encryptWithoutBib(paddedMessage, key.public_key())
bleichenbacherAttackWithoutBib(cipherPaddedMessage, key.public_key(), key)
#cipher = encrypt(message, key.public_key())
#bleichenbacherAttack(cipher, key.public_key(), key)

