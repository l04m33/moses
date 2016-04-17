import asyncio
import random
import unittest.mock as mock
import moses.socks as socks


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


def ensure_dummy_addr(ip, port):
    if ip is None:
        ip = '127.0.0.1'
    if port is None:
        port = random.randint(30000, 60000)
    return (ip, port)


@asyncio.coroutine
def dummy_socks_server_cb(reader, writer, fut):
    try:
        socks_req = yield from socks.handshake(reader, writer)
        yield from socks.handshake_done(socks_req, reader, writer)
    except Exception as exc:
        fut.set_exception(exc)
    else:
        fut.set_result(socks_req)


def run_dummy_socks_server(ev, ip=None, port=None):
    try:
        # This function runs in another thread, so we create the event
        # loop by ourselves.
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        ip, port = ensure_dummy_addr(ip, port)
        fut = asyncio.Future()
        cb = lambda r, w: dummy_socks_server_cb(r, w, fut)
        starter = asyncio.start_server(
                cb, host=ip, port=port, reuse_address=True)
        server = loop.run_until_complete(starter)
    finally:
        # server started (or failed to start), tell the client
        ev.set()
    loop.run_until_complete(fut)

    server.close()
    loop.run_until_complete(server.wait_closed())
    return fut.result()


