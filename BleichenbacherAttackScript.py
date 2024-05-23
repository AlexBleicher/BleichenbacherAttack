from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse
import random


# Simuliere das Padding-Orakel
def pkcs1_v15_pad(message, key_length):
    # Berechne die maximale Länge der Nachricht
    max_message_length = key_length - 11  # Für PKCS#1 v1.5 Padding

    # Überprüfe, ob die Nachricht zu lang ist
    if len(message) > max_message_length:
        raise ValueError("Die Nachricht ist zu lang für das PKCS#1 v1.5 Padding")

    # Berechne die Anzahl der benötigten Padding-Bytes
    pad_length = key_length - len(message) - 3

    # Generiere das Padding
    padding = b"\x00\x02" + bytes([random.randint(1, 255) for _ in range(pad_length)]) + b"\x00"

    # Kombiniere das Padding mit der Nachricht
    padded_message = padding + message

    return padded_message


def encrypt(message, e, n):
    messageAsInt = int.from_bytes(message, byteorder='big')
    return pow(messageAsInt, e, n)


def decrypt(cipher, d, n):
    plaintextAsInt = pow(cipher, d, n)
    return plaintextAsInt.to_bytes(128, 'big')


class Oracle:
    def __init__(self, d, n):
        self.d = d
        self.n = n

    def query(self, cipher):
        plaintextDec = decrypt(cipher, self.d, self.n)
        return plaintextDec[0:2] == b'\x00\x02'


class Bleichenbacher:
    def __init__(self, oracle, e, n, B):
        self.oracle = oracle
        self.e = e
        self.n = n
        self.B = B
        self.M = [(2 * B, 3 * B - 1)]
        self.s = (n + 2 * B) // (3 * B - 1)

    def find_next_s(self, ciphertext):
        originalS = self.s
        while True:
            self.s += 1
            encrypteds = encrypt(self.s.to_bytes(128, 'big'), self.e, self.n)
            cipherToTest = (encrypteds * ciphertext) % self.n
            if oracle.query(cipherToTest):
                print("Steps needed: " + str(self.s - originalS))
                return self.s

    def bleichenbacher_attack(self, ciphertext):
        self.find_next_s(ciphertext)
        a0 = self.M[0][0]
        b0 = self.M[0][1]
        lowerT = (self.s * a0 - b0) // self.n
        upperT = (self.s * b0 - a0) // self.n + 1
        M_next = []
        for t in range(lowerT, upperT):
            new_a = max(a0, (a0 + t * self.n) // self.s)
            new_b = min(b0, (b0 + t * self.n) // self.s)
            if new_a <= new_b:
                M_next.append((new_a, new_b))
        self.M = M_next
        print(self.M)
        print("Intervalllength: " + str(self.M[0][1] - self.M[0][0]))
        # End of phase 1
        runOnce = False
        while len(self.M) > 1 or not runOnce:
            runOnce = True
            self.find_next_s(ciphertext)
            M_next = []
            for a, b in self.M:
                lowerR = (self.s * a) // self.n
                upperR = (self.s * b) // self.n + 1
                for r in range(lowerR, upperR):
                    new_a = max(self.s * a, a0 + r * self.n)
                    new_b = min(self.s * b, b0 + r * self.n)
                    if new_a <= new_b:
                        M_next.append((max(a, (a0 + r * self.n) // self.s), min(b, (b0 + r * self.n) // self.s + 1)))
            self.M = M_next
        print(self.M)
        print("Intervalllength: " + str(self.M[0][1] - self.M[0][0]))
        # End of phase 2
        while True:
            # self.s *= 2
            self.find_next_s(ciphertext)
            M_next = []
            for a, b in self.M:
                lowerR = (self.s * a) // self.n
                upperR = (self.s * b) // self.n + 1
                for r in range(lowerR, upperR):
                    new_a = max(self.s * a, a0 + r * self.n)
                    new_b = min(self.s * b, b0 + r * self.n)
                    if new_a <= new_b:
                        M_next.append((max(a, (a0 + r * self.n) // self.s), min(b, (b0 + r * self.n) // self.s + 1)))
            self.M = M_next
            print(self.M)
            print("Intervalllength: " + str(self.M[0][1] - self.M[0][0]))
            if self.M[0][0] == self.M[0][1]:
                return self.M[0][0].to_bytes(128, 'big')


# Generiere ein RSA-Schlüsselpaar
key = RSA.generate(1024)
plaintext = b"Secret message"
paddedmessage = pkcs1_v15_pad(plaintext, 128)
cipher = encrypt(paddedmessage, key.e, key.n)
decrypted = decrypt(cipher, key.d, key.n)
oracle = Oracle(key.d, key.n)
B = pow(256, 126)  # B=256^k-2
bleichenbacher = Bleichenbacher(oracle, key.e, key.n, B)
# Führe den Angriff durch
decrypted_message = bleichenbacher.bleichenbacher_attack(cipher)
print("Ursprüngliche Nachricht:", paddedmessage)
print("Entschlüsselte Nachricht:", decrypted_message)
