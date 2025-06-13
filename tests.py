from time import time

from werkzeug_encryptedcookie import EncryptedCookie, SecureEncryptedCookie


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
        key = b'my little key'
        for case in [b'{"a": "b"}', b'{"a": "pr\xc3\xb3ba"}']:
            r1 = self.Cookie.encrypt(case, key)
            r2 = self.Cookie.encrypt(case, key)
            assert isinstance(r1, bytes)
            assert isinstance(r2, bytes)
            assert r1 != r2

            r1_broken = self.Cookie.decrypt(r1, b'another key')
            assert r1_broken != case

            r1 = self.Cookie.decrypt(r1, key)
            r2 = self.Cookie.decrypt(r2, key)
            assert r1 == case
            assert r2 == case

    def test_serialize_unserialize(self):
        key = b'my little key'
        for case in [{'a': 'b'}, {'a': 'próba'}, {'próba': '123'}]:
            r = self.Cookie(case, key).serialize()
            assert isinstance(r, bytes)
            # Check it is ascii
            r.decode('ascii')

            r = self.Cookie.unserialize(r, key)
            assert r == case

    def test_unserialize_binary(self):
        """
        Test unserialize compatibility with existing binary data.
        """
        key = b'my little key'
        for case in [
                b'GXCS2JfvmfQJwuxYUITWTmnanyjkIP0IHKbZF2u7oz2qnuIRGuzJbF5JhZrp',
                b'bvK0dvBIBuPqIrG+o4Zmmu6ln7bLoR+xTz906R8GQAAAaM2rlncYNzsKIsmU',
        ]:
            r = self.Cookie.unserialize(case, key)
            assert {'a': 'próba'} == dict(r)

    def test_expires(self):
        key = b'my little key'
        c = self.Cookie({'a': 'próba'}, key)

        r = self.Cookie.unserialize(c.serialize(time() - 1), key)
        assert not r

        # Make sure previous expire not stored in cookie object.
        # (such bug present in original SecureCookie)
        r = self.Cookie.unserialize(c.serialize(), key)
        assert r

        r = self.Cookie.unserialize(c.serialize(time() + 1), key)
        assert r

    def test_fail_with_another_key(self):
        c = self.Cookie({'a': 'próba'}, 'one key')
        r = self.Cookie.unserialize(c.serialize(), b'another key')
        assert not r

    def test_fail_when_not_json(self):
        key = b'my little key'
        r = self.RawCookie.encrypt(b'{"a", "pr\xc3\xb3ba"}', key)
        r = self.RawCookie.unserialize(r, key)
        assert not r

    def test_fail_when_corrupted(self):
        key = b'my little key'
        r = self.RawCookie({"a": "próba"}, key).serialize()
        r = self.RawCookie.unserialize(r[:20] + r[21:], key)
        assert not r

    def test_compression_and_decompression(self):
        key = b'my little key'
        case = {'a': 'próba'}
        no_compress = self.NoCompressCookie(case, key)
        compress = self.CompressCookie(case, key)
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
            result = cookie2.unserialize(cookie1.serialize(), key)
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
        key, case = b'my little key', b'{"a": "pr\xc3\xb3ba"}'
        r = self.Cookie.encrypt(case, key)
        signed = EncryptedCookie.decrypt(r, key)
        assert case in signed

        r = EncryptedCookie.encrypt(signed, key)
        r = self.Cookie.decrypt(r, key)
        assert r == case

        r = EncryptedCookie.encrypt(signed[:-1] + b'!', key)
        r = self.Cookie.decrypt(r, key)
        assert r == b''

    def test_unserialize_binary(self):
        """
        Test unserialize compatibility with existing binary data.
        """
        key = b'my little key'
        for case in [
                b'vGSOoyvh3KREQNzFhAbhl/oSugKPMJ8QDvp4VWRtSpgUA3670wlkbv1kzA15HQ9oBw==',
                b'78EM1wnaIkz6FP0EDxHPk6xeGFam2w6cSr6FWosRf6X3H7ILJvhA+gkuq+6AT9iD6g=='
        ]:
            r = self.Cookie.unserialize(case, key)
            assert {'a': 'próba'} == dict(r)
