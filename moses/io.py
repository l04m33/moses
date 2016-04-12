import asyncio
import struct
import traceback
from concurrent.futures import FIRST_COMPLETED
from .log import logger


class UDPRelayProtocol(asyncio.Protocol):
    def __init__(self, stream_down):
        super().__init__()
        self._stream_down = stream_down

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data, _addr):
        data_len = struct.pack('>H', len(data))
        # TODO: flow control?
        self._stream_down.write(data_len)
        self._stream_down.write(data)

    def error_received(self, exc):
        logger('io').debug('error_received: %a', exc)

    def connection_lost(self, exc):
        logger('io').debug('connection_lost: %a', exc)


@asyncio.coroutine
def sync_write(writer, data):
    writer.write(data)
    return (yield from writer.drain())


@asyncio.coroutine
def streaming(reader, writer, block_size):
    data = yield from reader.read(block_size)
    while len(data) > 0:
        yield from sync_write(writer, data)
        data = yield from reader.read(block_size)
    if writer.can_write_eof():
        writer.write_eof()
        return True
    else:
        return False


@asyncio.coroutine
def do_connect(addr, port, ssl=None):
    connect_op = asyncio.async(asyncio.open_connection(addr, port, ssl=ssl))
    try:
        proxy_reader, proxy_writer = \
                yield from asyncio.wait_for(connect_op, None)
    except:
        connect_op.cancel()     # for python version < 3.4.3
        logger('io').debug(traceback.format_exc())
        return None

    if ssl is not None:
        cur_cipher = proxy_writer.get_extra_info('cipher')
        logger('io').debug('Current cipher: %s', cur_cipher)

    return (proxy_reader, proxy_writer)


@asyncio.coroutine
def do_streaming(reader, writer, remote_reader, remote_writer, bs):
    stream_up = asyncio.async(streaming(reader, remote_writer, bs))
    stream_down = asyncio.async(streaming(remote_reader, writer, bs))

    done, pending = yield from \
            asyncio.wait([stream_up, stream_down], return_when=FIRST_COMPLETED)

    for f in done:
        try:
            f.result()
        except:
            logger('io').debug(traceback.format_exc())

    for f in pending:
        f.cancel()
