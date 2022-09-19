import os
import time
import json
import getpass
import hmac
import hashlib
import base64
import uuid
import contextlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import fxa.core
import fxa.crypto
import syncclient.client


CRYPTO_BACKEND = default_backend()


def make_password_record(username, password, system):
    now = int(time.time() * 1000)
    hostname = f'https://{system}'
    return {
        "id": f"{uuid.uuid4()}",
        "username": username,
        "password": password,
        "hostname": hostname,
        "formSubmitURL": hostname,
        "usernameField": "username",
        "passwordField": "password",
        "timeCreated": now,
        "timePasswordChanged": now,
        "httpRealm": None,
    }


def check_verified(session):
    while True:
        status = session.get_email_status()
        if status["verified"]:
            break
        print("Please click through the confirmation email.")
        if input("Hit enter when done, or type 'resend': ") == "resend":
            session.resend_email_code()


@contextlib.contextmanager
def closing(session):
    try:
        yield session
    finally:
        session.destroy_session()


class Client:
    def login(self):
        client = fxa.core.Client()
        email = input('Firefox email: ')
        password = getpass.getpass('Firefox password: ')
        # TODO: Need to get a real client id, but how?
        client_id = 'keyrings.firefox'
        with closing(client.login(email, password, keys=True)) as session:
            check_verified(session)
            self.access_token, self.refresh_token = \
                syncclient.client.create_oauth_token(session, client_id)
            _, self.kB = session.fetch_keys()
            self.client = syncclient.client.get_sync_client(
                session, client_id, self.access_token)
        self._build_keys()

    @property
    def access_token(self):
        return self.t

    def _build_keys(self):
        raw_sync_key = fxa.crypto.derive_key(self.kB, "oldsync", 64)
        root_key_bundle = KeyBundle(
            raw_sync_key[:32],
            raw_sync_key[32:],
        )
        keys_bso = self.client.get_record("crypto", "keys")
        keys = root_key_bundle.decrypt_bso(keys_bso)
        self.default_key_bundle = KeyBundle(
            base64.b64decode(keys["default"][0]),
            base64.b64decode(keys["default"][1]),
        )

    def encrypt(self, record):
        encrypted = self.default_key_bundle.encrypt_bso(record)
        assert self.decrypt(encrypted) == record
        return encrypted

    def decrypt(self, encrypted):
        return self.default_key_bundle.decrypt_bso(encrypted)

    def set_password(self, record):
        self.client.put_record("passwords", self.encrypt(record))

    def get_passwords(self):
        records = self.client.get_records("passwords")
        return map(self.decrypt, records)


class KeyBundle:
    """A little helper class to hold a sync key bundle."""

    def __init__(self, enc_key, mac_key):
        self.enc_key = enc_key
        self.mac_key = mac_key

    def decrypt_bso(self, data):
        payload = json.loads(data["payload"])

        mac = hmac.new(self.mac_key, payload["ciphertext"], hashlib.sha256)
        if mac.hexdigest() != payload["hmac"]:
            raise ValueError(
                "hmac mismatch: %r != %r" % (mac.hexdigest(), payload["hmac"])
            )

        iv = base64.b64decode(payload["IV"])
        cipher = Cipher(
            algorithms.AES(self.enc_key),
            modes.CBC(iv),
            backend=CRYPTO_BACKEND,
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(base64.b64decode(payload["ciphertext"]))
        plaintext += decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()

        return json.loads(plaintext)

    def encrypt_bso(self, data):
        plaintext = json.dumps(data)

        padder = padding.PKCS7(128).padder()
        plaintext = padder.update(plaintext) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.enc_key),
            modes.CBC(iv),
            backend=CRYPTO_BACKEND,
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext)
        ciphertext += encryptor.finalize()

        b64_ciphertext = base64.b64encode(ciphertext)
        mac = hmac.new(self.mac_key, b64_ciphertext, hashlib.sha256).hexdigest()

        return {
            "id": data["id"],
            "payload": json.dumps(
                {
                    "ciphertext": b64_ciphertext,
                    "IV": base64.b64encode(iv),
                    "hmac": mac,
                }
            ),
        }
