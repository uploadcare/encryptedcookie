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

    def encrypt(self, data: bytes) -> bytes:
        nonce = secrets.token_bytes(16)
        cipher = self._get_cipher(nonce)
        return nonce + cipher.encrypt(data)

    @classmethod
    def compress(cls, data: bytes) -> bytes:
        return cls.compress_cookie_header + brotli.compress(data, quality=8)

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

    @classmethod
    def loads(cls, data: bytes) -> dict:
        return json.loads(data.decode('utf-8'))

    def decrypt(self, string: bytes) -> bytes:
        nonce, payload = string[:16], string[16:]

        cipher = self._get_cipher(nonce)
        return cipher.decrypt(payload)

    @classmethod
    def decompress(cls, data: bytes) -> bytes:
        if data.startswith(cls.compress_cookie_header):
            body = data[len(cls.compress_cookie_header):]
            try:
                return brotli.decompress(body)
            except brotli.error:
                pass

        return data

    def unserialize(self, string: bytes) -> dict:
        if self.quote_base64:
            try:
                string = base64.b64decode(string)
            except Exception:
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
