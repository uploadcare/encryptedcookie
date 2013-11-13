# encoding: utf-8
import unittest
from time import time

from werkzeug_encryptedcookie import EncryptedCookie


class EncruptedCookieTest(unittest.TestCase):

    def test_dumps_loads(self):
        for case in [{'a': 'b'}, {'a': u'próba'}, {u'próba': '123'}]:
            r = EncryptedCookie.dumps(case)
            self.assertIsInstance(r, bytes, case)

            r = EncryptedCookie.loads(r)
            self.assertEqual(r, case)

    def test_encrypt_decrypt(self):
        key = 'my little key'
        for case in ['{"a": "b"}', '{"a": "próba"}']:
            r1 = EncryptedCookie.encrypt(case, key)
            r2 = EncryptedCookie.encrypt(case, key)
            self.assertIsInstance(r1, bytes, case)
            self.assertIsInstance(r2, bytes, case)
            self.assertNotEqual(r1, r2, case)

            r1_broken = EncryptedCookie.decrypt(r1, 'another key')
            self.assertNotEqual(r1_broken, case)

            r1 = EncryptedCookie.decrypt(r1, key)
            r2 = EncryptedCookie.decrypt(r2, key)
            self.assertEqual(r1, case)
            self.assertEqual(r2, case)

    def test_serialize_unserialize(self):
        key = 'my little key'
        for case in [{'a': 'b'}, {'a': u'próba'}, {u'próba': '123'}]:
            r = EncryptedCookie(case, key).serialize()
            self.assertIsInstance(r, bytes, case)
            self.assertEqual(r, r.decode('ascii'), case)

            r = EncryptedCookie.unserialize(r, key)
            self.assertEqual(r, case)
            self.assertEqual(dict(r), case)

    def test_expires(self):
        key = 'my little key'
        c = EncryptedCookie({'a': u'próba'}, key)

        r = EncryptedCookie.unserialize(c.serialize(time() - 1), key)
        self.assertFalse(dict(r))

        # Make sure previous expire not stored in cookie object.
        # (such bug present in original SecureCookie)
        r = EncryptedCookie.unserialize(c.serialize(), key)
        self.assertTrue(dict(r))

        r = EncryptedCookie.unserialize(c.serialize(time() + 1), key)
        self.assertTrue(dict(r))

    def test_fail_with_another_key(self):
        c = EncryptedCookie({'a': u'próba'}, 'one key')
        r = EncryptedCookie.unserialize(c.serialize(), 'another key')
        self.assertFalse(dict(r))

    def test_fail_when_not_json(self):
        key = 'my little key'
        Cookie = type('Cookie', (EncryptedCookie,), {'quote_base64': False})

        r = Cookie.encrypt('{"a", "próba"}', key)
        r = Cookie.unserialize(r, key)
        self.assertFalse(dict(r))

    def test_fail_when_corrupted(self):
        key = 'my little key'
        Cookie = type('Cookie', (EncryptedCookie,), {'quote_base64': False})

        r = Cookie({"a": u"próba"}, key).serialize()
        r = Cookie.unserialize(r[:20] + r[21:], key)
        self.assertFalse(dict(r))

if __name__ == '__main__':
    unittest.main()
