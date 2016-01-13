#!/usr/bin/env python3

#
# Moses: A simple Socks5 proxy that encrypts your connections using TLS.
#
# Use the `-h` option to see usage info.
#

# 
#   Then Moses stretched out his hand over the sea, and all that night
#   the Lord drove the sea back with a strong east wind and turned it
#   into dry land. The waters were divided, and the Israelites went
#   through the sea on dry ground, with a wall of water on their right
#   and on their left. ( Exodus 14:21-22 )
#

#
# The MIT License (MIT)
# Copyright (c) 2015 Kay Z.
# 
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#

import asyncio
from concurrent.futures import FIRST_COMPLETED
import ssl
import functools
import logging
import traceback
import argparse
import sys
import struct


DEFAULT_BLOCK_SIZE = 2048


logger = logging.getLogger(__file__)


class VersionNotSupportedError(Exception):
    pass


class UDPRelayProtocol(asyncio.Protocol):
    def __init__(self, stream_down):
        super().__init__()
        self._stream_down = stream_down

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data, _addr):
        data_len = struct.pack('>H', len(data))
        self._stream_down.write(data_len)
        self._stream_down.write(data)

    def error_received(self, exc):
        logger.debug('error_received: %a', exc)

    def connection_lost(self, exc):
        logger.debug('connection_lost: %a', exc)


def socks_check_version(ver):
    if ver != 0x05:
        logger.debug('Protocol version %d not supported', ver)
        raise VersionNotSupportedError('Bad version: {}'.format(ver))


@asyncio.coroutine
def socks_recv_auth_method_list(reader):
    header = yield from reader.readexactly(2)
    socks_check_version(header[0])
    methods = header[1]
    if methods > 0:
        method_list = yield from reader.readexactly(methods)
    else:
        method_list = b''
    return method_list


@asyncio.coroutine
def socks_recv_request(reader):
    header = yield from reader.readexactly(4)
    socks_check_version(header[0])

    if header[3] == 0x01:       # ip
        ip_binary = yield from reader.readexactly(4)
        address = '{}.{}.{}.{}'.format(
            ip_binary[0], ip_binary[1], ip_binary[2], ip_binary[3])
    elif header[3] == 0x03:     # domain name
        domain_len = (yield from reader.readexactly(1))[0]
        address = (yield from reader.readexactly(domain_len)).decode()
    elif header[3] == 0x04:     # ipv6
        ip_binary = yield from reader.readexactly(16)
        address = ('{:02x}{:02x}:' * 7 + '{:02x}{:02x}').format(
            ip_binary[0], ip_binary[1], ip_binary[2], ip_binary[3],
            ip_binary[4], ip_binary[5], ip_binary[6], ip_binary[7],
            ip_binary[8], ip_binary[9], ip_binary[10], ip_binary[11],
            ip_binary[12], ip_binary[13], ip_binary[14], ip_binary[15])

    port_binary = yield from reader.readexactly(2)
    port = (port_binary[0] << 8) + port_binary[1]

    #       command,   addr_type
    return (header[1], header[3], address, port)


@asyncio.coroutine
def socks_handshake(reader, writer):
    try:
        method_list = yield from socks_recv_auth_method_list(reader)

        if 0x0 not in method_list:
            logger.debug('No proper method found')
            yield from sync_write(writer, b'\x05\xff')
            return None

        yield from sync_write(writer, b'\x05\x00')

        command, addr_type, address, port = \
                yield from socks_recv_request(reader)

        if command not in supported_socks_commands:
            logger.debug('Bad command: %d', command)
            yield from sync_write(
                writer, b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            return None
    except:
        logger.debug(traceback.format_exc())
        return None

    return (command, addr_type, address, port)


@asyncio.coroutine
def socks_handshake_done(socks_req, reader, writer):
    yield from sync_write(
        writer, b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')


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
        logger.debug(traceback.format_exc())
        return None

    if ssl is not None:
        cur_cipher = proxy_writer.get_extra_info('cipher')
        logger.debug('Current cipher: %s', cur_cipher)

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
            logger.debug(traceback.format_exc())

    for f in pending:
        f.cancel()


@asyncio.coroutine
def cmd_connect(socks_req, reader, writer, params):
    _command, _addr_type, address, port = socks_req

    logger.debug('Connecting to %s:%d', address, port)

    remote_rw = yield from do_connect(address, port)
    if remote_rw is None:
        writer.close()
        return

    bs = params.get('bs', DEFAULT_BLOCK_SIZE)
    try:
        yield from socks_handshake_done(socks_req, reader, writer)
        yield from do_streaming(reader, writer, remote_rw[0], remote_rw[1], bs)
    finally:
        remote_rw[1].close()


@asyncio.coroutine
def cmd_udp_relay(socks_req, reader, writer, params):
    _command, _addr_type, address, port = socks_req

    logger.debug('Relaying UDP packets to %s:%d', address, port)

    loop = asyncio.get_event_loop()
    relay_transport, _relay_protocol = \
            yield from loop.create_datagram_endpoint(
                    lambda: UDPRelayProtocol(writer),
                    remote_addr=(address, port))

    try:
        yield from socks_handshake_done(socks_req, reader, writer)
        while True:
            data_len_buf = yield from reader.readexactly(2)
            data_len, = struct.unpack('>H', data_len_buf)
            data = yield from reader.readexactly(data_len)
            relay_transport.sendto(data)
    except asyncio.IncompleteReadError:
        logger.debug('UDP_RELAY connection terminated')
    except:
        logger.debug(traceback.format_exc())
    finally:
        relay_transport.close()


supported_socks_commands = {
    0x01: cmd_connect,
    0x81: cmd_udp_relay,
}


@asyncio.coroutine
def server_connection_cb(reader, writer, params):
    socks_req = yield from socks_handshake(reader, writer)
    if socks_req is None:
        writer.close()
        return

    cmd_handler = supported_socks_commands[socks_req[0]]

    yield from cmd_handler(socks_req, reader, writer, params)


@asyncio.coroutine
def client_connection_cb(reader, writer, params):
    server_addr = params['server_addr']
    bs = params.get('bs', DEFAULT_BLOCK_SIZE)
    ssl_ctx = params.get('ssl_ctx', None)

    remote_rw = yield from do_connect(server_addr[0], server_addr[1], ssl=ssl_ctx)
    if remote_rw is None:
        writer.close()
        return

    yield from do_streaming(reader, writer, remote_rw[0], remote_rw[1], bs)

    remote_rw[1].close()
    writer.close()


def build_ssl_ctx(my_certs_file, peer_certs_file, ciphers=None):
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    if ciphers is not None:
        ssl_ctx.set_ciphers(ciphers)
    ssl_ctx.options |= ssl.OP_NO_SSLv2
    ssl_ctx.options |= ssl.OP_NO_SSLv3
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    ssl_ctx.check_hostname = False
    ssl_ctx.load_cert_chain(my_certs_file)
    ssl_ctx.load_verify_locations(peer_certs_file)
    return ssl_ctx


def server_main(loop, args):
    logger.info('Moses server listening at %s', args.bind)

    if args.forward is not None:
        logger.info('Forwarding client connections to %s', args.forward)
        try:
            forward_addr = parse_ip_port(args.forward)
        except:
            logger.error('Bad forwarding address: %s', args.forward)
            sys.exit(1)
        params = {
            'server_addr': forward_addr,
            'bs': args.block_size,
        }
        cb = functools.partial(client_connection_cb, params=params)
    else:
        params = { 'bs': args.block_size }
        cb = functools.partial(server_connection_cb, params=params)

    if args.no_tls:
        logger.warning('Connections from clients are NOT encrypted')
        ssl_ctx = None
    else:
        ssl_ctx = build_ssl_ctx(args.local_cert, args.remote_cert, args.ciphers)

    local_ip, local_port = parse_ip_port(args.bind)
    starter = asyncio.start_server(cb, local_ip, local_port,
            ssl=ssl_ctx,
            backlog=args.backlog,
            reuse_address=True,
            loop=loop)
    return loop.run_until_complete(starter)


def client_main(loop, args):
    logger.info('Moses client listening at %s', args.bind)
    logger.info('Forwarding to %s', args.peer)

    if args.peer is None:
        logger.error('No peer (server) address provided')
        sys.exit(1)

    try:
        server_addr = parse_ip_port(args.peer)
    except:
        logger.error('Bad peer address: %s', args.peer)
        sys.exit(1)

    if args.no_tls:
        logger.warning('Connections to the server are NOT encrypted')
        ssl_ctx = None
    else:
        ssl_ctx = build_ssl_ctx(args.local_cert, args.remote_cert, args.ciphers)

    params = {
        'server_addr': server_addr,
        'bs': args.block_size,
        'ssl_ctx': ssl_ctx,
    }
    cb = functools.partial(client_connection_cb, params=params)

    local_ip, local_port = parse_ip_port(args.bind)
    starter = asyncio.start_server(cb, local_ip, local_port,
            backlog=args.backlog,
            reuse_address=True,
            loop=loop)
    return loop.run_until_complete(starter)


def parse_arguments():
    parser = argparse.ArgumentParser()

    common_group = parser.add_argument_group('Common Options')

    mode_group = common_group.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('-c', '--client',
            help='Client mode',
            action='store_true')
    mode_group.add_argument('-s', '--server',
            help='Server mode',
            action='store_true')

    common_group.add_argument('-b', '--bind',
            metavar='<ADDRESS>:<PORT>',
            help='IP & port to bind (default: <all interfaces>:1080)',
            default=':1080',
            type=str)
    common_group.add_argument('-n', '--no-tls',
            help='Do not use TLS encryption',
            action='store_true')
    common_group.add_argument('-l', '--local-cert',
            help='Local SSL certificates (default: ./local.pem)',
            default='./local.pem',
            type=str)
    common_group.add_argument('-r', '--remote-cert',
            help='Remote SSL certificates (default: ./remote.pem)',
            default='./remote.pem',
            type=str)
    common_group.add_argument('-e', '--ciphers',
            help='Ciphers to use for encryption. '
                 'Run `openssl ciphers` to see available ciphers',
            type=str)
    common_group.add_argument('--backlog',
            help='Backlog for the listening socket (default: 128)',
            default=128,
            type=int)
    common_group.add_argument('--loglevel',
            help='Log level (default: info)',
            default='info',
            type=str,
            choices=[
                'critical', 'fatal', 'error',
                'warning', 'info', 'debug',
                ])
    common_group.add_argument('--block-size',
            help='Block size for data streaming, in bytes (default: 2048)',
            default=DEFAULT_BLOCK_SIZE,
            type=int)

    client_group = parser.add_argument_group('Client Options')

    client_group.add_argument('-p', '--peer',
            metavar='<ADDRESS>:<PORT>',
            help='Peer (server) address',
            type=str)

    server_group = parser.add_argument_group('Server Options')

    server_group.add_argument('-f', '--forward',
            metavar='<ADDRESS>:<PORT>',
            help='Simply forward all connections to the given address',
            type=str)

    return parser.parse_args()


def parse_ip_port(addr_str):
    last_col = addr_str.rfind(':')
    return (addr_str[0:last_col], int(addr_str[last_col+1:]))


def main():
    args = parse_arguments()
    logging.basicConfig(
            level=args.loglevel.upper(),
            format='%(asctime)s:%(levelname)s:%(name)s:%(message)s')

    loop = asyncio.get_event_loop()

    if args.client:
        server = client_main(loop, args)
    elif args.server:
        server = server_main(loop, args)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


if __name__ == '__main__':
    main()
