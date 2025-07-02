from __future__ import annotations

import base64
import json
import secrets
import struct
import zlib
from datetime import timedelta
from hashlib import sha1
from time import time

import brotli
from Crypto.Cipher import ARC4


def _date_to_unix(arg: float | int | timedelta):
    """
    Converts int or timedelta object into the seconds from epoch in UTC.
    """
    if isinstance(arg, timedelta):
        arg = time() + arg.total_seconds()
    return int(arg)


class EncryptedCookie:
    quote_base64 = True
    compress_cookie = True
    compress_cookie_header = b'~!~brtl~!~'

    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key

    def _get_cipher(self, nonce: bytes) -> ARC4.ARC4Cipher:
        return ARC4.new(sha1(self.secret_key + nonce).digest())

    @classmethod
    def dumps(cls, data: dict) -> bytes:
        return json.dumps(data, ensure_ascii=False).encode()

    @classmethod
    def compress(cls, data: bytes) -> bytes:
        return cls.compress_cookie_header + brotli.compress(data, quality=8)

    def encrypt(self, data: bytes) -> bytes:
        nonce = secrets.token_bytes(16)
        cipher = self._get_cipher(nonce)
        return nonce + cipher.encrypt(data)

    def serialize(
            self, data: dict, expires: float | int | timedelta | None = None
    ) -> bytes:
        data = data.copy()
        if expires is not None:
            data['_expires'] = _date_to_unix(expires)

        payload = self.dumps(data)

        if self.compress_cookie:
            payload = self.compress(payload)

        string = self.encrypt(payload)

        if self.quote_base64:
            string = base64.b64encode(string)

        return string

    def serialize_str(
            self, data: dict, expires: float | int | timedelta | None = None
    ) -> str:
        string = self.serialize(data, expires)
        if self.quote_base64:
            return string.decode('ascii')
        else:
            return string.hex()

    @classmethod
    def loads(cls, data: bytes) -> dict:
        return json.loads(data.decode())

    @classmethod
    def decompress(cls, data: bytes) -> bytes:
        if data.startswith(cls.compress_cookie_header):
            body = data[len(cls.compress_cookie_header):]
            try:
                return brotli.decompress(body)
            except brotli.error:
                pass

        return data

    def decrypt(self, string: bytes) -> bytes:
        nonce, payload = string[:16], string[16:]

        cipher = self._get_cipher(nonce)
        return cipher.decrypt(payload)

    def unserialize(self, string: bytes) -> dict:
        if self.quote_base64:
            try:
                string = base64.b64decode(string)
            except ValueError:
                pass

        payload = self.decrypt(string)
        payload = self.decompress(payload)

        try:
            data = self.loads(payload)
        except ValueError:
            data = {}

        if data and '_expires' in data:
            if time() > data['_expires']:
                data = {}
            else:
                del data['_expires']

        return data

    def unserialize_str(self, string: str) -> dict:
        if self.quote_base64:
            data = string.encode()
        else:
            try:
                data = bytes.fromhex(string)
            except ValueError:
                data = string.encode()
        return self.unserialize(data)


class SecureEncryptedCookie(EncryptedCookie):
    def encrypt(self, data: bytes) -> bytes:
        crc = zlib.crc32(data, zlib.crc32(self.secret_key))
        data += struct.pack('>I', crc & 0xffffffff)
        return super().encrypt(data)

    def decrypt(self, string: bytes) -> bytes:
        data = super().decrypt(string)
        data, crc1 = data[:-4], data[-4:]
        crc2 = zlib.crc32(data, zlib.crc32(self.secret_key))
        if crc1 != struct.pack('>I', crc2 & 0xffffffff):
            return b''
        return data
