from datetime import timedelta
from time import time

from encryptedcookie import EncryptedCookie, SecureEncryptedCookie


class TestEncryptedCookie:
    Cookie = EncryptedCookie

    class RawCookie(Cookie):
        quote_base64 = False

    class NoCompressCookie(Cookie):
        compress_cookie = False

    # Explicit setup for tests
    class CompressCookie(Cookie):
        compress_cookie = True

    def test_dumps_loads(self):
        for case in [{'a': 'b'}, {'a': 'próba'}, {'próba': '123'}]:
            r = self.Cookie.dumps(case)
            assert isinstance(r, bytes)

            r = self.Cookie.loads(r)
            assert r == case

    def test_encrypt_decrypt(self):
        cookie = self.Cookie(b'my little key')
        for case in [b'{"a": "b"}', b'{"a": "pr\xc3\xb3ba"}']:
            r1 = cookie.encrypt(case)
            r2 = cookie.encrypt(case)
            assert isinstance(r1, bytes)
            assert isinstance(r2, bytes)
            assert r1 != r2

            r1_broken = self.Cookie(b'another key').decrypt(r1)
            assert r1_broken != case

            r1 = cookie.decrypt(r1)
            r2 = cookie.decrypt(r2)
            assert r1 == case
            assert r2 == case

    def test_serialize_unserialize(self):
        cookie = self.Cookie(b'my little key')
        for case in [{'a': 'b'}, {'a': 'próba'}, {'próba': '123'}]:
            r = cookie.serialize(case)
            assert isinstance(r, bytes)
            # Check it is ascii
            r.decode('ascii')

            r = cookie.unserialize(r)
            assert r == case

    def test_unserialize_binary(self):
        """
        Test unserialize compatibility with existing binary data.
        """
        cookie = self.Cookie(b'my little key')
        for case in [
                b'GXCS2JfvmfQJwuxYUITWTmnanyjkIP0IHKbZF2u7oz2qnuIRGuzJbF5JhZrp',
                b'bvK0dvBIBuPqIrG+o4Zmmu6ln7bLoR+xTz906R8GQAAAaM2rlncYNzsKIsmU',
        ]:
            r = cookie.unserialize(case)
            assert {'a': 'próba'} == dict(r)

    def test_expires(self):
        cookie = self.Cookie(b'my little key')
        data = {'a': 'próba'}
        c = cookie

        r = cookie.unserialize(c.serialize(data, time() - 1))
        assert not r

        # Make sure previous expire not stored in cookie object.
        # (such bug present in original SecureCookie)
        r = cookie.unserialize(c.serialize(data))
        assert r == data

        r = cookie.unserialize(c.serialize(data, time() + 1))
        assert r == data

        r = cookie.unserialize(c.serialize(data, timedelta(-1)))
        assert not r

        r = cookie.unserialize(c.serialize(data, timedelta(1)))
        assert r == data

    def test_fail_with_another_key(self):
        r = self.Cookie(b'one key').serialize({'a': 'próba'})
        r = self.Cookie(b'another key').unserialize(r)
        assert not r

    def test_fail_when_not_json(self):
        cookie = self.RawCookie(b'my little key')
        r = cookie.encrypt(b'{"a", "pr\xc3\xb3ba"}')
        r = cookie.unserialize(r)
        assert not r

    def test_fail_when_corrupted(self):
        cookie = self.RawCookie(b'my little key')
        r = cookie.serialize({'a': 'próba'})
        r = cookie.unserialize(r[:20] + r[21:])
        assert not r

    def test_compression_and_decompression(self):
        key = b'my little key'
        case = {'a': 'próba'}
        no_compress = self.NoCompressCookie(key)
        compress = self.CompressCookie(key)
        cases = (
            # No-compressed instance unserialized by no-compressed instance
            (no_compress, no_compress),
            # No-compress instance unserialized by compress instance
            (no_compress, compress),
            # Compressed instance unserialized by no-compress instance
            (compress, no_compress),
            # Compressed instance unserialized by compress instance
            (compress, compress),
        )
        for cookie1, cookie2 in cases:
            result = cookie2.unserialize(cookie1.serialize(case))
            assert result == case


class TestSecureEncryptedCookie(TestEncryptedCookie):
    Cookie = SecureEncryptedCookie

    class RawCookie(Cookie):  # pyright: ignore[reportIncompatibleVariableOverride]
        quote_base64 = False

    class NoCompressCookie(  # pyright: ignore[reportIncompatibleVariableOverride]
            Cookie):
        compress_cookie = False

    # Explicit setup for tests
    class CompressCookie(Cookie):  # pyright: ignore[reportIncompatibleVariableOverride]
        compress_cookie = True

    def test_unsigned(self):
        secure_cookie = self.Cookie(b'my little key')
        unsecure_cookie = EncryptedCookie(b'my little key')
        case = b'{"a": "pr\xc3\xb3ba"}'

        # Check that encrypted data is the same as in original cookie
        r = secure_cookie.encrypt(case)
        signed = unsecure_cookie.decrypt(r)
        assert case == signed[:-4]

        # Should be the same as secure_cookie.encrypt(case)
        r = unsecure_cookie.encrypt(signed)
        r = secure_cookie.decrypt(r)
        assert r == case

        # Try to fake signature
        r = unsecure_cookie.encrypt(case + b'xxxx')
        r = secure_cookie.decrypt(r)
        assert r == b''

    def test_unserialize_binary(self):
        """
        Test unserialize compatibility with existing binary data.
        """
        cookie = self.Cookie(b'my little key')
        for case in [
                b'vGSOoyvh3KREQNzFhAbhl/oSugKPMJ8QDvp4VWRtSpgUA3670wlkbv1kzA15HQ9oBw==',
                b'78EM1wnaIkz6FP0EDxHPk6xeGFam2w6cSr6FWosRf6X3H7ILJvhA+gkuq+6AT9iD6g=='
        ]:
            r = cookie.unserialize(case)
            assert {'a': 'próba'} == dict(r)
