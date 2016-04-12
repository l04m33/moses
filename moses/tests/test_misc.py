import unittest
import moses.misc as misc


class TestParsers(unittest.TestCase):
    def test_parse_ip_port(self):
        ret = misc.parse_ip_port('123.234.1.2:443')
        self.assertEqual(ret, ('123.234.1.2', 443))
        ret = misc.parse_ip_port(':443')
        self.assertEqual(ret, ('', 443))
