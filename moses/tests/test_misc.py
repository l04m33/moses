import unittest
import moses.misc as misc


class TestParsers(unittest.TestCase):
    def test_parse_ip_port(self):
        ret = misc.parse_ip_port('123.234.1.2:443')
        self.assertEqual(ret, ('123.234.1.2', 443))
        ret = misc.parse_ip_port(':443')
        self.assertEqual(ret, ('', 443))

    def test_parse_keepalive_params(self):
        ret = misc.parse_keepalive_params('1,2,3')
        self.assertEqual(ret, (1, 2, 3))
        with self.assertRaises(AssertionError):
            misc.parse_keepalive_params('1,2')
        with self.assertRaises(AssertionError):
            misc.parse_keepalive_params('1')
