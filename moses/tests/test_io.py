import unittest
import asyncio
import moses.io as io
from . import dummy


class TestUDPRelayProtocol(unittest.TestCase):
    def test_datagram_received(self):
        writer_mock, dummy_write = dummy.make_dummy_writer()
        udp_relay = io.UDPRelayProtocol(writer_mock)
        udp_relay.datagram_received(b'123456789', ('127.0.0.1', 1234))
        self.assertEqual(dummy_write.buf, b'\x00\x09123456789')


class TestTCPStreaming(unittest.TestCase):
    def test_sync_write(self):
        writer_mock, dummy_write = dummy.make_dummy_writer()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(io.sync_write(writer_mock, b'123456789'))
        writer_mock.drain.assert_called_once_with()
        self.assertEqual(dummy_write.buf, b'123456789')

    def test_streaming_with_eof(self):
        reader = asyncio.StreamReader()
        writer_mock, dummy_write = dummy.make_dummy_writer()

        reader.feed_data(b'123456789')
        reader.feed_eof()

        loop = asyncio.get_event_loop()
        ret = loop.run_until_complete(io.streaming(reader, writer_mock, 4))

        self.assertEqual(ret, True)
        writer_mock.write_eof.assert_called_once_with()
        self.assertEqual(dummy_write.buf, b'123456789')

    def test_streaming_without_eof(self):
        reader = asyncio.StreamReader()
        writer_mock, dummy_write = dummy.make_dummy_writer(can_write_eof=False)

        reader.feed_data(b'123456789')
        reader.feed_eof()

        loop = asyncio.get_event_loop()
        ret = loop.run_until_complete(io.streaming(reader, writer_mock, 4))

        self.assertEqual(ret, False)
        writer_mock.write_eof.assert_not_called()
        self.assertEqual(dummy_write.buf, b'123456789')
