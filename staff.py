#!/usr/bin/env python3

#
# Moses' Staff: A transparent proxy that works with moses.py, for Linux systems.
#
# Use the `-h` option to see usage info.
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

import socket
import struct
import ctypes
import asyncio
from concurrent.futures import FIRST_COMPLETED
import argparse
import functools
import logging
import traceback
import sys
import random


DEFAULT_BLOCK_SIZE = 2048
SO_ORIGINAL_DST = 80


logger = logging.getLogger(__file__)


conn_pool = {}


class sin_addr(ctypes.Structure):
    _fields_ = [
        ('s_addr', ctypes.c_uint32)
    ]


class sockaddr_in(ctypes.Structure):
    _fields_ = [
        ('sin_family', ctypes.c_int16),
        ('sin_port',   ctypes.c_uint16),
        ('sin_addr',   sin_addr),
        ('sin_zero',   ctypes.c_uint8 * 8)
    ]


class UDPRelayProtocol(asyncio.DatagramProtocol):
    def __init__(self, proxy, dns_server, loop):
        self._proxy = proxy
        self._dns = dns_server
        self._loop = loop

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data, addr):
        dns = random.choice(self._dns)
        fut = asyncio.async(
                forward_udp_msg_up(
                    data, addr, dns, self._proxy, self._transport))
        fut.add_done_callback(forward_udp_msg_up_done)

    def error_received(self, exc):
        logger.debug(exc)

    def connection_lost(self, exc):
        if exc is not None:
            logger.debug(exc)


def parse_ip_port(addr_str):
    last_col = addr_str.rfind(':')
    return (addr_str[0:last_col], int(addr_str[last_col+1:]))


def parse_dns_servers(dns_str):
    return [parse_ip_port(d) for d in dns_str.split(',')]


@asyncio.coroutine
def open_socks_connection(proxy, cmd, dst):
    reader, writer = yield from asyncio.open_connection(proxy[0], proxy[1])

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


@asyncio.coroutine
def forward_udp_msg_down(reader, transport, dst):
    msg_len_buf = yield from reader.readexactly(2)
    msg_len, = struct.unpack('>H', msg_len_buf)
    msg = yield from reader.readexactly(msg_len)
    transport.sendto(msg, addr=dst)
    logger.debug('Got UDP msg for %a', dst)


def clean_up_bad_conn(dst, exc):
    logger.debug(
            'Lost the connection %s:%d to Moses server, cleaning up',
            dst[0], dst[1])
    conn_pool[dst].set_exception(exc)
    # in case there's no coroutine waiting for this future,
    # prevent asyncio from complaining about never retrieved exceptions
    conn_pool[dst].exception()
    del conn_pool[dst]


def forward_udp_msg_down_done(fut, dst, conn):
    try:
        fut.result()
    except (asyncio.IncompleteReadError, asyncio.CancelledError) as exc:
        clean_up_bad_conn(dst, exc)
        return
    except:
        logger.debug(traceback.format_exc())

    logger.debug('Releasing UDP relay connection %a', dst)

    waiter = conn_pool[dst]
    conn_pool[dst] = conn
    waiter.set_result(conn)


@asyncio.coroutine
def forward_udp_msg_up(msg, src, dst, proxy, transport):
    conn = conn_pool.get(dst)

    if conn is None:
        # No existing connection found. Create a new one.
        conn_op = asyncio.async(open_socks_connection(proxy, 0x81, dst))
        conn_pool[dst] = asyncio.Future()
        logger.debug('Creating UDP relay connection %a', dst)
        try:
            reader, writer = yield from asyncio.wait_for(conn_op, None)
        except Exception as exc:
            # We still have the lock, clean it up ASAP
            clean_up_bad_conn(dst, exc)
            raise
        logger.debug('Done creating UDP relay connection %a', dst)

    elif isinstance(conn, asyncio.Future):
        # Connecting or busy, we wait for the connection
        logger.debug('Waiting for UDP relay connection %a', dst)
        reader, writer = yield from asyncio.wait_for(conn, None)
        while isinstance(conn_pool[dst], asyncio.Future):
            logger.debug('Connection %a is busy. Keep waiting.', dst)
            reader, writer = yield from asyncio.wait_for(conn_pool[dst], None)
        logger.debug('Acquired UDP relay connection %a', dst)
        conn_pool[dst] = asyncio.Future()

    else:
        reader, writer = conn
        conn_pool[dst] = asyncio.Future()

    fut = asyncio.async(forward_udp_msg_down(reader, transport, src))
    fut.add_done_callback(
            functools.partial(
                forward_udp_msg_down_done, dst=dst, conn=(reader, writer)))

    msg_len = struct.pack('>H', len(msg))
    writer.write(msg_len)
    writer.write(msg)
    try:
        yield from writer.drain()
    except Exception as exc:
        fut.cancel()
        raise

    logger.debug('UDP msg sent to %a', dst)


def forward_udp_msg_up_done(fut):
    try:
        fut.result()
    except:
        logger.debug(traceback.format_exc())

    logger.debug('forward_udp_msg_up_done')


def create_udp_server(loop, addr, port, proxy, dns_servers):
    logger.info('UDP server listening on %s:%d', addr, port)
    ep_op = loop.create_datagram_endpoint(
            lambda: UDPRelayProtocol(proxy, dns_servers, loop),
            local_addr=(addr, port), reuse_address=True)
    return loop.run_until_complete(ep_op)


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
def tcp_server_cb(reader, writer, proxy, bs):
    sock = writer.get_extra_info('socket')

    orig_dst_buf = \
            sock.getsockopt(
                    socket.SOL_IP, SO_ORIGINAL_DST, ctypes.sizeof(sockaddr_in))
    orig_dst = sockaddr_in.from_buffer_copy(orig_dst_buf)

    logger.debug(
            'orig_dst = (%d, %d)',
            orig_dst.sin_addr.s_addr, orig_dst.sin_port)

    try:
        proxy_reader, proxy_writer = yield from open_socks_connection(
                proxy, 0x01, (orig_dst.sin_addr.s_addr, orig_dst.sin_port))
    except:
        logger.debug(traceback.format_exc())
        return

    try:
        yield from do_streaming(reader, writer, proxy_reader, proxy_writer, bs)
    except:
        logger.debug(traceback.format_exc())
    finally:
        proxy_writer.close()


def create_tcp_server(loop, addr, port, proxy, backlog, bs):
    logger.info('TCP server listening on %s:%d', addr, port)
    cb = functools.partial(tcp_server_cb, proxy=proxy, bs=bs)
    srv_op = asyncio.start_server(
            cb, host=addr, port=port,
            reuse_address=True, backlog=backlog, loop=loop)
    return loop.run_until_complete(srv_op)


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('-t', '--tcp-port',
            help='The TCP port to listen on (default: 32000)',
            default='32000',
            type=int)
    parser.add_argument('-u', '--udp-port',
            help='The UDP port to listen on (default: 32000)',
            default='32000',
            type=int)
    parser.add_argument('-p', '--proxy',
            metavar='<ADDRESS>:<PORT>',
            help='Moses proxy address (default: 127.0.0.1:1080)',
            default='127.0.0.1:1080',
            type=str)
    parser.add_argument('-d', '--dns',
            metavar='<ADDRESS>:<PORT>[,<ADDRESS>:<PORT>...]',
            help='Name server address (default: 8.8.8.8:53,8.8.4.4:53)',
            default='8.8.8.8:53,8.8.4.4:53',
            type=str)
    parser.add_argument('--block-size',
            help='Block size for data streaming, in bytes (default: 2048)',
            default=DEFAULT_BLOCK_SIZE,
            type=int)
    parser.add_argument('--backlog',
            help='Backlog for the listening socket (default: 128)',
            default=128,
            type=int)
    parser.add_argument('--loglevel',
            help='Log level (default: info)',
            default='info',
            type=str,
            choices=[
                'critical', 'fatal', 'error',
                'warning', 'info', 'debug',
                ])

    return parser.parse_args()


def main():
    args = parse_arguments()
    logging.basicConfig(
            level=args.loglevel.upper(),
            format='%(asctime)s:%(levelname)s:%(name)s:%(message)s')

    loop = asyncio.get_event_loop()

    _transport, _protocol = \
            create_udp_server(
                    loop, '127.0.0.1', args.udp_port,
                    parse_ip_port(args.proxy),
                    parse_dns_servers(args.dns))

    _server = \
            create_tcp_server(
                    loop, '127.0.0.1', args.tcp_port,
                    parse_ip_port(args.proxy),
                    args.backlog,
                    args.block_size)

    loop.run_forever()


if __name__ == '__main__':
    main()
