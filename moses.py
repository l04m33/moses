#!/bin/env python3

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
import ssl
import functools
import logging
import traceback
import argparse
import sys


DEFAULT_BLOCK_SIZE = 2048


logger = logging.getLogger(__file__)


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
def server_connection_cb(reader, writer, bs=DEFAULT_BLOCK_SIZE):
    try:
        method_list = yield from socks_recv_auth_method_list(reader)
    except:
        logger.debug(traceback.format_exc())
        writer.close()
        return

    if 0x0 not in method_list:
        logger.debug('No proper method found')
        yield from sync_write(writer, b'\x05\xff')
        writer.close()

    yield from sync_write(writer, b'\x05\x00')

    try:
        command, addr_type, address, port = \
                yield from socks_recv_request(reader)
    except:
        logger.debug(traceback.format_exc())
        writer.close()
        return

    logger.debug('Connecting to %s:%d', address, port)

    if command != 0x01:     # XXX: only support the CONNECT command
        logger.debug('Bad command: %d', command)
        yield from sync_write(
            writer, b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
        writer.close()
        return

    connect_op = asyncio.async(asyncio.open_connection(address, port))
    try:
        proxy_reader, proxy_writer = \
                yield from asyncio.wait_for(connect_op, None)
    except:
        connect_op.cancel()     # for python version < 3.4.3
        logger.debug(traceback.format_exc())
        writer.close()
        return

    yield from sync_write(
        writer, b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')

    stream_up = asyncio.async(streaming(reader, proxy_writer, bs))
    stream_down = asyncio.async(streaming(proxy_reader, writer, bs))

    try:
        st_down_stat = yield from asyncio.wait_for(stream_down, None)
    except:
        stream_down.cancel()
        logger.debug(traceback.format_exc())

    if stream_up.done():
        try:
            stream_up.result()
        except:
            logger.debug(traceback.format_exc())
    else:
        stream_up.cancel()

    proxy_writer.close()
    writer.close()


@asyncio.coroutine
def client_connection_cb(reader, writer, server_addr, bs=DEFAULT_BLOCK_SIZE, ssl_ctx=None):
    connect_op = asyncio.async(
        asyncio.open_connection(server_addr[0], server_addr[1], ssl=ssl_ctx))
    try:
        proxy_reader, proxy_writer = \
                yield from asyncio.wait_for(connect_op, None)
    except:
        connect_op.cancel()     # for python version < 3.4.3
        logger.debug(traceback.format_exc())
        writer.close()
        return

    stream_up = asyncio.async(streaming(reader, proxy_writer, bs))
    stream_down = asyncio.async(streaming(proxy_reader, writer, bs))

    try:
        st_up_stat = yield from asyncio.wait_for(stream_up, None)
    except:
        stream_up.cancel()
        logger.debug(traceback.format_exc())

    if stream_down.done():
        try:
            stream_down.result()
        except:
            logger.debug(traceback.format_exc())
    else:
        stream_down.cancel()

    proxy_writer.close()
    writer.close()


def build_ssl_ctx(my_certs_file, peer_certs_file):
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ssl_ctx.options |= ssl.OP_NO_SSLv2
    ssl_ctx.options |= ssl.OP_NO_SSLv3
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    ssl_ctx.check_hostname = False
    ssl_ctx.load_cert_chain(my_certs_file)
    ssl_ctx.load_verify_locations(peer_certs_file)
    return ssl_ctx


def server_main(loop, args):
    logger.info('Moses server listening at %s', args.bind)

    cb = functools.partial(server_connection_cb, bs=args.block_size)

    ssl_ctx = build_ssl_ctx(args.local_cert, args.remote_cert)

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

    ssl_ctx = build_ssl_ctx(args.local_cert, args.remote_cert)
    cb = functools.partial(client_connection_cb,
            server_addr=server_addr,
            bs=args.block_size,
            ssl_ctx=ssl_ctx)

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
    common_group.add_argument('-l', '--local-cert',
            help='Local SSL certificates (default: ./local.pem)',
            default='./local.pem',
            type=str)
    common_group.add_argument('-r', '--remote-cert',
            help='Remote SSL certificates (default: ./remote.pem)',
            default='./remote.pem',
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

    return parser.parse_args()


def parse_ip_port(addr_str):
    last_col = addr_str.rfind(':')
    return (addr_str[0:last_col], int(addr_str[last_col+1:]))


def main():
    args = parse_arguments()
    logging.basicConfig(level=args.loglevel.upper())

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
