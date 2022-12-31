from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class DiffieHellman:
    def __init__(self, curve="SECP384R1"):
        if curve == "SECP256R1":
            self.diffieHellman = ec.generate_private_key(ec.SECP256R1(), default_backend())
        elif curve == "SECP384R1":
            self.diffieHellman = ec.generate_private_key(ec.SECP384R1(), default_backend())
        elif curve == "SECP521R1":
            self.diffieHellman = ec.generate_private_key(ec.SECP521R1(), default_backend())
        elif curve == "SECP224R1":
            self.diffieHellman = ec.generate_private_key(ec.SECP224R1(), default_backend())
        elif curve == "SECP192R1":
            self.diffieHellman = ec.generate_private_key(ec.SECP192R1(), default_backend())
        elif curve == "SECP256K1":
            self.diffieHellman = ec.generate_private_key(ec.SECP256K1(), default_backend())
        elif curve == "BrainpoolP256R1":
            self.diffieHellman = ec.generate_private_key(ec.BrainpoolP256R1(), default_backend())
        elif curve == "BrainpoolP384R1":
            self.diffieHellman = ec.generate_private_key(ec.BrainpoolP384R1(), default_backend())
        elif curve == "BrainpoolP512R1":
            self.diffieHellman = ec.generate_private_key(ec.BrainpoolP512R1(), default_backend())
        elif curve == "SECT571K1":
            self.diffieHellman = ec.generate_private_key(ec.SECT571K1(), default_backend())
        elif curve == "SECT409K1":
            self.diffieHellman = ec.generate_private_key(ec.SECT409K1(), default_backend())
        elif curve == "SECT283K1":
            self.diffieHellman = ec.generate_private_key(ec.SECT283K1(), default_backend())
        elif curve == "SECT233K1":
            self.diffieHellman = ec.generate_private_key(ec.SECT233K1(), default_backend())
        elif curve == "SECT163K1":
            self.diffieHellman = ec.generate_private_key(ec.SECT163K1(), default_backend())
        elif curve == "SECT571R1":
            self.diffieHellman = ec.generate_private_key(ec.SECT571R1(), default_backend())
        elif curve == "SECT409R1":
            self.diffieHellman = ec.generate_private_key(ec.SECT409R1(), default_backend())
        elif curve == "SECT283R1":
            self.diffieHellman = ec.generate_private_key(ec.SECT283R1(), default_backend())
        elif curve == "SECT233R1":
            self.diffieHellman = ec.generate_private_key(ec.SECT233R1(), default_backend())
        else:
            self.diffieHellman = ec.generate_private_key(ec.SECT163R2(), default_backend())
        self.public_key = self.diffieHellman.public_key()
        self.IV = b'a'*16

    def encrypt(self, public_key, secret):
        shared_key = self.diffieHellman.exchange(ec.ECDH(), public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(shared_key)

        aes = Cipher(algorithms.AES(derived_key), modes.CBC(self.IV), backend=default_backend())
        encryptor = aes.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(secret.encode()) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, public_key, secret, iv):
        shared_key = self.diffieHellman.exchange(ec.ECDH(), public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(shared_key)

        aes = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
        decryptor = aes.decryptor()
        decrypted_data = decryptor.update(secret) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()
