#!/usr/bin/env python

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from secrets import token_bytes


class DiffieHellman:

    def __init__(self):
        self.diffieHellman = ec.generate_private_key(ec.SECP256K1())
        self.public_key = self.diffieHellman.public_key()

    def _aead(self, public_key):
        shared_key = self.diffieHellman.exchange(ec.ECDH(), public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(),
                           length=32,
                           salt=None,
                           info=b"tron-ecdh-example").derive(shared_key)
        return AESGCM(derived_key)

    def encrypt(self, public_key, secret):
        nonce = token_bytes(12)
        return nonce + self._aead(public_key).encrypt(nonce, secret.encode(), None)

    def decrypt(self, public_key, data):
        return self._aead(public_key).decrypt(data[:12], data[12:], None)


text = "Hello World!"

alice = DiffieHellman()
bob = DiffieHellman()

encrypted_message = bob.encrypt(alice.public_key, text)
print(encrypted_message)

decrypted_message = alice.decrypt(bob.public_key, encrypted_message)
print(decrypted_message)
