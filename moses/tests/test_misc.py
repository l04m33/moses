import unittest
import moses.misc as misc
import moses.defaults as defaults


class TestParsers(unittest.TestCase):
    def test_parse_ip_port(self):
        ret = misc.parse_ip_port('123.234.1.2:443')
        self.assertEqual(ret, ('123.234.1.2', 443))
        ret = misc.parse_ip_port('123.234.1.2')
        self.assertEqual(ret, ('123.234.1.2', defaults.BINDING_PORT))
        ret = misc.parse_ip_port('[fe80:0000:0000:0000:1234:5678:90ab:cdef]:443')
        self.assertEqual(ret, ('fe80:0000:0000:0000:1234:5678:90ab:cdef', 443))
        ret = misc.parse_ip_port('fe80:0000:0000:0000:1234:5678:90ab:cdef')
        self.assertEqual(ret, ('fe80:0000:0000:0000:1234:5678:90ab:cdef', defaults.BINDING_PORT))
        ret = misc.parse_ip_port('[::1]:443')
        self.assertEqual(ret, ('::1', 443))
        ret = misc.parse_ip_port('::1')
        self.assertEqual(ret, ('::1', defaults.BINDING_PORT))
        ret = misc.parse_ip_port('www.example.com:443')
        self.assertEqual(ret, ('www.example.com', 443))
        ret = misc.parse_ip_port('www.example.com')
        self.assertEqual(ret, ('www.example.com', defaults.BINDING_PORT))
        ret = misc.parse_ip_port(':443')
        self.assertEqual(ret, ('', 443))

    def test_parse_keepalive_params(self):
        ret = misc.parse_keepalive_params('1,2,3')
        self.assertEqual(ret, (1, 2, 3))
        with self.assertRaises(AssertionError):
            misc.parse_keepalive_params('1,2')
        with self.assertRaises(AssertionError):
            misc.parse_keepalive_params('1')
