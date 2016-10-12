import asyncio
import struct
import socket
import sys
import traceback
from . import defaults
from . import io
from .log import logger


@asyncio.coroutine
def cmd_connect(socks_req, reader, writer, params):
    _command, _addr_type, address, port = socks_req

    logger('socks').debug('Connecting to %s:%d', address, port)

    keepalive = params.get('keepalive', None)
    remote_rw = yield from io.do_connect(address, port, keepalive=keepalive)
    if remote_rw is None:
        writer.close()
        return

    bs = params.get('bs', defaults.BLOCK_SIZE)
    try:
        yield from handshake_done(socks_req, reader, writer)
        yield from io.do_streaming(reader, writer, remote_rw[0], remote_rw[1], bs)
    finally:
        remote_rw[1].close()


@asyncio.coroutine
def cmd_udp_relay(socks_req, reader, writer, params):
    _command, _addr_type, address, port = socks_req

    logger('socks').debug('Relaying UDP packets to %s:%d', address, port)

    loop = asyncio.get_event_loop()
    relay_transport, _relay_protocol = \
            yield from loop.create_datagram_endpoint(
                    lambda: io.UDPRelayProtocol(writer),
                    remote_addr=(address, port))

    try:
        yield from handshake_done(socks_req, reader, writer)
        while True:
            data_len_buf = yield from reader.readexactly(2)
            data_len, = struct.unpack('>H', data_len_buf)
            data = yield from reader.readexactly(data_len)
            relay_transport.sendto(data)
    except asyncio.IncompleteReadError:
        logger('socks').debug('UDP_RELAY connection terminated')
    except:
        logger('socks').debug(traceback.format_exc())
    finally:
        relay_transport.close()


supported_cmds = {
    0x01: cmd_connect,
    0x81: cmd_udp_relay,
}


class VersionNotSupportedError(Exception):
    pass


class AddressTypeNotSupportedError(Exception):
    pass


def check_version(ver):
    if ver != 0x05:
        logger('socks').debug('Protocol version %d not supported', ver)
        raise VersionNotSupportedError('Bad version: {}'.format(ver))


@asyncio.coroutine
def recv_auth_method_list(reader):
    header = yield from reader.readexactly(2)
    check_version(header[0])
    methods = header[1]
    if methods > 0:
        method_list = yield from reader.readexactly(methods)
    else:
        method_list = b''
    return method_list


@asyncio.coroutine
def recv_request(reader):
    header = yield from reader.readexactly(4)
    check_version(header[0])

    if header[3] == 0x01:       # ip
        ip_binary = yield from reader.readexactly(4)
        address = '{}.{}.{}.{}'.format(
            ip_binary[0], ip_binary[1], ip_binary[2], ip_binary[3])
    elif header[3] == 0x03:     # domain name
        domain_len = (yield from reader.readexactly(1))[0]
        address = (yield from reader.readexactly(domain_len)).decode()
    elif header[3] == 0x04:     # ipv6
        ip_binary = yield from reader.readexactly(16)
        address = ('{:02x}{:02x}:' * 7 + '{:02x}{:02x}').format(*ip_binary)
    else:
        raise AddressTypeNotSupportedError(
                'Bad address type: {}'.format(header[3]))

    port_binary = yield from reader.readexactly(2)
    port = (port_binary[0] << 8) + port_binary[1]

    #       command,   addr_type
    return (header[1], header[3], address, port)


@asyncio.coroutine
def handshake(reader, writer):
    try:
        method_list = yield from recv_auth_method_list(reader)

        if 0x0 not in method_list:
            logger('socks').debug('No proper method found')
            yield from io.sync_write(writer, b'\x05\xff')
            return None

        yield from io.sync_write(writer, b'\x05\x00')

        command, addr_type, address, port = \
                yield from recv_request(reader)

        if command not in supported_cmds:
            logger('socks').debug('Bad command: %d', command)
            yield from io.sync_write(
                writer, b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            return None
    except:
        logger('socks').debug(traceback.format_exc())
        return None

    return (command, addr_type, address, port)


@asyncio.coroutine
def handshake_done(socks_req, reader, writer):
    yield from io.sync_write(
        writer, b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')


@asyncio.coroutine
def open_connection(proxy, cmd, dst):
    conn = yield from io.do_connect(proxy[0], proxy[1])
    if conn is None:
        raise RuntimeError('Failed to open socks connection to {}', proxy)
    reader, writer = conn

    try:
        writer.write(b'\x05\x01\x00')
        yield from writer.drain()

        res = yield from reader.readexactly(2)
        assert res == b'\x05\x00'

        if isinstance(dst[0], str):
            addr_buf = socket.inet_aton(dst[0])
            port_buf = dst[1].to_bytes(2, 'big')
        else:
            addr_buf = dst[0].to_bytes(4, sys.byteorder)
            port_buf = dst[1].to_bytes(2, sys.byteorder)
        writer.write(b'\x05' + cmd.to_bytes(1, sys.byteorder) +
                b'\x00\x01' + addr_buf + port_buf)

        res = yield from reader.readexactly(10)
        assert res == b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    except:
        writer.close()
        raise

    return (reader, writer)
