import unittest
import asyncio
import threading
import concurrent.futures as futures
import moses.socks as socks
from . import dummy


class TestSocksProcedure(unittest.TestCase):
    def test_check_version(self):
        socks.check_version(0x05)
        with self.assertRaises(socks.VersionNotSupportedError):
            socks.check_version(0x04)
        with self.assertRaises(socks.VersionNotSupportedError):
            socks.check_version(0x06)

    def test_recv_auth_method_list(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b'\x05\x00')

        loop = asyncio.get_event_loop()

        ret = loop.run_until_complete(socks.recv_auth_method_list(reader))
        self.assertEqual(len(ret), 0)

        reader.feed_data(b'\x05\x04\x00\01\x02\x03')

        ret = loop.run_until_complete(socks.recv_auth_method_list(reader))
        self.assertEqual(ret, b'\x00\x01\x02\x03')

    def test_recv_request_ip(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b'\x05\x01\x00\x01\x01\x02\x03\x04\x00\x09')

        loop = asyncio.get_event_loop()
        ret = loop.run_until_complete(socks.recv_request(reader))
        self.assertEqual(ret, (0x01, 0x01, '1.2.3.4', 9))

    def test_recv_request_domain(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b'\x05\x01\x00\x03\x0ewww.google.com\x01\xbb')

        loop = asyncio.get_event_loop()
        ret = loop.run_until_complete(socks.recv_request(reader))
        self.assertEqual(ret, (0x01, 0x03, 'www.google.com', 443))

    def test_recv_request_ipv6(self):
        reader = asyncio.StreamReader()
        reader.feed_data(
                b'\x05\x01\x00\x04' +
                b'\x01\x02\x03\x04\x05\x06\x07\x08' +
                b'\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10' +
                b'\x00\xff')

        loop = asyncio.get_event_loop()
        ret = loop.run_until_complete(socks.recv_request(reader))
        self.assertEqual(ret,
                (0x01, 0x04, '0102:0304:0506:0708:090a:0b0c:0d0e:0f10', 255))

    def test_recv_request_unknown(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b'\x05\x01\x00\xab\x01\x02\x03\x04\x00\x09')

        loop = asyncio.get_event_loop()
        with self.assertRaises(socks.AddressTypeNotSupportedError):
            loop.run_until_complete(socks.recv_request(reader))

    def test_handshake_no_method(self):
        reader = asyncio.StreamReader()
        (writer_mock, dummy_write) = dummy.make_dummy_writer()

        loop = asyncio.get_event_loop()

        reader.feed_data(b'\x05\x02\x01\x03')

        ret = loop.run_until_complete(socks.handshake(reader, writer_mock))
        self.assertEqual(ret, None)

    def test_handshake_not_supported_cmd(self):
        reader = asyncio.StreamReader()
        (writer_mock, dummy_write) = dummy.make_dummy_writer()

        loop = asyncio.get_event_loop()

        reader.feed_data(b'\x05\x01\x00')
        reader.feed_data(b'\x05\xff\x00\x01\x01\x02\x03\x04\x00\x09')

        ret = loop.run_until_complete(socks.handshake(reader, writer_mock))
        self.assertEqual(ret, None)
        self.assertEqual(dummy_write.buf,
                b'\x05\x00' +
                b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')

    def test_handshake(self):
        reader = asyncio.StreamReader()
        (writer_mock, dummy_write) = dummy.make_dummy_writer()

        loop = asyncio.get_event_loop()

        reader.feed_data(b'\x05\x01\x00')
        reader.feed_data(b'\x05\x01\x00\x01\x01\x02\x03\x04\x00\x09')

        ret = loop.run_until_complete(socks.handshake(reader, writer_mock))
        self.assertEqual(ret, (0x01, 0x01, '1.2.3.4', 9))
        self.assertEqual(dummy_write.buf, b'\x05\x00')

    def test_open_connection(self):
        s_addr = dummy.ensure_dummy_addr(None, None)
        ev = threading.Event()
        with futures.ThreadPoolExecutor(max_workers=1) as executor:
            server_fut = executor.submit(
                    dummy.run_dummy_socks_server, ev, *s_addr)
            ev.wait()
            loop = asyncio.get_event_loop()
            reader, writer = \
                    loop.run_until_complete(
                            socks.open_connection(
                                s_addr, 0x01, ('1.2.3.4', 53)))
            ret = server_fut.result()
            self.assertEqual(ret, (0x01, 0x01, '1.2.3.4', 53))
