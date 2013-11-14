# encoding: utf-8
try:
    import unittest2 as unittest
except ImportError:
    import unittest
from time import time

from werkzeug_encryptedcookie import EncryptedCookie, SecureEncryptedCookie


class EncruptedCookieTest(unittest.TestCase):
    Cookie = EncryptedCookie
    RawCookie = type('RawCookie', (Cookie,), {'quote_base64': False})

    def test_dumps_loads(self):
        for case in [{'a': 'b'}, {'a': u'próba'}, {u'próba': '123'}]:
            r = self.Cookie.dumps(case)
            self.assertIsInstance(r, bytes, case)

            r = self.Cookie.loads(r)
            self.assertEqual(r, case)

    def test_encrypt_decrypt(self):
        key = 'my little key'
        for case in [b'{"a": "b"}', b'{"a": "próba"}']:
            r1 = self.Cookie.encrypt(case, key)
            r2 = self.Cookie.encrypt(case, key)
            self.assertIsInstance(r1, bytes, case)
            self.assertIsInstance(r2, bytes, case)
            self.assertNotEqual(r1, r2, case)

            r1_broken = self.Cookie.decrypt(r1, 'another key')
            self.assertNotEqual(r1_broken, case)

            r1 = self.Cookie.decrypt(r1, key)
            r2 = self.Cookie.decrypt(r2, key)
            self.assertEqual(r1, case)
            self.assertEqual(r2, case)

    def test_serialize_unserialize(self):
        key = 'my little key'
        for case in [{'a': 'b'}, {'a': u'próba'}, {u'próba': '123'}]:
            r = self.Cookie(case, key).serialize()
            self.assertIsInstance(r, bytes, case)
            self.assertEqual(r, r.decode('ascii'), case)

            r = self.Cookie.unserialize(r, key)
            self.assertEqual(r, case)
            self.assertEqual(dict(r), case)

    def test_expires(self):
        key = 'my little key'
        c = self.Cookie({'a': u'próba'}, key)

        r = self.Cookie.unserialize(c.serialize(time() - 1), key)
        self.assertFalse(dict(r))

        # Make sure previous expire not stored in cookie object.
        # (such bug present in original SecureCookie)
        r = self.Cookie.unserialize(c.serialize(), key)
        self.assertTrue(dict(r))

        r = self.Cookie.unserialize(c.serialize(time() + 1), key)
        self.assertTrue(dict(r))

    def test_fail_with_another_key(self):
        c = self.Cookie({'a': u'próba'}, 'one key')
        r = self.Cookie.unserialize(c.serialize(), 'another key')
        self.assertFalse(dict(r))

    def test_fail_when_not_json(self):
        key = 'my little key'
        r = self.RawCookie.encrypt(b'{"a", "próba"}', key)
        r = self.RawCookie.unserialize(r, key)
        self.assertFalse(dict(r))

    def test_fail_when_corrupted(self):
        key = 'my little key'
        r = self.RawCookie({"a": u"próba"}, key).serialize()
        r = self.RawCookie.unserialize(r[:20] + r[21:], key)
        self.assertFalse(dict(r))


class SecureEncryptedCookieTest(EncruptedCookieTest):
    Cookie = SecureEncryptedCookie
    RawCookie = type('RawCookie', (Cookie,), {'quote_base64': False})

    def test_unsigned(self):
        key, case = 'my little key', b'{"a": "próba"}'
        r = self.Cookie.encrypt(case, key)
        signed = EncryptedCookie.decrypt(r, key)
        self.assertIn(case, signed)

        r = EncryptedCookie.encrypt(signed, key)
        r = self.Cookie.decrypt(r, key)
        self.assertEqual(r, case)

        r = EncryptedCookie.encrypt(signed[:-1] + b'!', key)
        r = self.Cookie.decrypt(r, key)
        self.assertEqual(r, b'')


if __name__ == '__main__':
    unittest.main()
