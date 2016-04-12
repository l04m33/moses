import asyncio
import unittest.mock as mock


class DummyWrite:
    def __init__(self):
        self.buf = bytearray()

    def __call__(self, data):
        self.buf.extend(data)


@asyncio.coroutine
def dummy_drain():
    yield from asyncio.sleep(0.001)


def make_dummy_writer(can_write_eof=True):
    writer_mock = mock.Mock(spec=asyncio.StreamWriter)
    dummy_write = DummyWrite()
    writer_mock.attach_mock(mock.Mock(wraps=dummy_write), 'write')
    writer_mock.attach_mock(mock.Mock(wraps=dummy_drain), 'drain')
    writer_mock.attach_mock(
            mock.Mock(wraps=lambda: can_write_eof), 'can_write_eof')
    return (writer_mock, dummy_write)


