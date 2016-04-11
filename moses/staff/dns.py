import asyncio
import collections
import struct
import functools
import random
import traceback
from .. import socks
from ..log import logger


conn_pool = {}


DNSRelayConnection = \
        collections.namedtuple(
                'DNSRelayConnection',
                ('reader', 'writer', 'waiters', 'id_map'))


class DNSRelayProtocol(asyncio.DatagramProtocol):
    def __init__(self, proxy, dns_server, timeout, loop):
        self._proxy = proxy
        self._dns = dns_server
        self._timeout = timeout
        self._loop = loop

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data, addr):
        dns = random.choice(self._dns)
        fut = asyncio.async(
                forward_dns_msg(
                    data, addr, dns, self._proxy,
                    self._transport, self._timeout))
        fut.add_done_callback(forward_dns_msg_done)

    def error_received(self, exc):
        logger('staff.dns').debug(exc)

    def connection_lost(self, exc):
        if exc is not None:
            logger('staff.dns').debug(exc)


@asyncio.coroutine
def forward_dns_msg(msg, src, dst, proxy, transport, timeout):
    if len(msg) < 2:
        return

    relay_conn = yield from get_dns_conn(dst, proxy)
    reader, writer, waiters, id_map = relay_conn

    dns_id, = struct.unpack_from('>H', msg)
    logger('staff.dns').debug('dns_id = %d', dns_id)

    waiter_key = (src, dns_id)
    old_waiter = waiters.get(waiter_key)
    if old_waiter is not None:
        logger('staff.dns').debug(
                'Previous request from %r for ID %d is still pending, cancelling',
                src, dns_id)
        old_waiter.cancel()
    dns_waiter = asyncio.Future()
    waiters[waiter_key] = dns_waiter

    relay_dns_id = gen_dns_id(id_map)
    id_map[relay_dns_id] = waiter_key
    logger('staff.dns').debug('relay_dns_id = %d', relay_dns_id)

    msg_len = struct.pack('>H', len(msg))
    writer.write(msg_len)
    writer.write(struct.pack('>H', relay_dns_id) + msg[2:])
    try:
        yield from writer.drain()
    except Exception as exc:
        clean_up_bad_conn(dst, exc)
        del waiters[waiter_key]
        del id_map[relay_dns_id]
        raise

    logger('staff.dns').debug('UDP msg sent to %a', dst)
    logger('staff.dns').debug('Releasing DNS relay connection %a', dst)

    put_dns_conn(dst, relay_conn)

    try:
        resp_msg = yield from asyncio.wait_for(dns_waiter, timeout)
    except asyncio.TimeoutError:
        logger('staff.dns').debug(
                'DNS request %d from %r timed out', dns_id, src)
        if waiters[waiter_key] == dns_waiter:
            del waiters[waiter_key]
        del id_map[relay_dns_id]
        raise
    except:
        del id_map[relay_dns_id]
        raise

    logger('staff.dns').debug('Got DNS reply for %a, dns_id = %d', src, dns_id)
    transport.sendto(msg[:2] + resp_msg[2:], addr=src)


def forward_dns_msg_done(fut):
    try:
        fut.result()
    except:
        logger('staff.dns').debug(traceback.format_exc())

    logger('staff.dns').debug('forward_dns_msg_done')


@asyncio.coroutine
def get_dns_conn(dst, proxy):
    conn = conn_pool.get(dst)

    if conn is None:
        # No existing connection found. Create a new one.
        conn_op = asyncio.async(socks.open_connection(proxy, 0x81, dst))
        conn_pool[dst] = asyncio.Future()
        logger('staff.dns').debug('Creating DNS relay connection %a', dst)
        try:
            reader, writer = yield from asyncio.wait_for(conn_op, None)
        except Exception as exc:
            # We still have the lock, clean it up ASAP
            clean_up_bad_conn(dst, exc)
            raise
        waiters = {}
        id_map = {}
        dispatch_op = \
                asyncio.async(dns_resp_dispatcher(reader, waiters, id_map))
        dispatch_op.add_done_callback(
                functools.partial(
                    dns_resp_dispatcher_done, dst=dst, waiters=waiters))
        conn = DNSRelayConnection(reader, writer, waiters, id_map)
        logger('staff.dns').debug('Done creating DNS relay connection %a', dst)

    elif isinstance(conn, asyncio.Future):
        # Connecting or busy, we wait for the connection
        logger('staff.dns').debug('Waiting for DNS relay connection %a', dst)
        conn = yield from asyncio.wait_for(conn, None)
        while isinstance(conn_pool[dst], asyncio.Future):
            logger('staff.dns').debug('Connection %a is busy. Keep waiting.', dst)
            conn = yield from asyncio.wait_for(conn_pool[dst], None)
        logger('staff.dns').debug('Acquired DNS relay connection %a', dst)
        conn_pool[dst] = asyncio.Future()

    else:
        conn_pool[dst] = asyncio.Future()

    return conn


def put_dns_conn(dst, relay_conn):
    waiter = conn_pool[dst]
    conn_pool[dst] = relay_conn
    waiter.set_result(conn_pool[dst])


def clean_up_bad_conn(dst, exc):
    logger('staff.dns').debug(
            'Lost the connection %s:%d to Moses server, cleaning up',
            dst[0], dst[1])
    conn_pool[dst].set_exception(exc)
    # in case there's no coroutine waiting for this future,
    # prevent asyncio from complaining about never retrieved exceptions
    conn_pool[dst].exception()
    del conn_pool[dst]


@asyncio.coroutine
def dns_resp_dispatcher(reader, waiters, id_map):
    while True:
        msg_len_buf = yield from reader.readexactly(2)
        msg_len, = struct.unpack('>H', msg_len_buf)

        assert msg_len > 2

        msg = yield from reader.readexactly(msg_len)
        relay_dns_id, = struct.unpack_from('>H', msg)
        logger('staff.dns').debug('Got relayed DNS msg for ID %d', relay_dns_id)

        waiter_key = id_map.get(relay_dns_id)
        if waiter_key is not None:
            w = waiters.get(waiter_key)
            if isinstance(w, asyncio.Future):
                del waiters[waiter_key]
                w.set_result(msg)
            del id_map[relay_dns_id]
            logger('staff.dns').debug('Current id_map size: %d', len(id_map))


def dns_resp_dispatcher_done(fut, dst, waiters):
    try:
        fut.result()
    except Exception as exc:
        logger('staff.dns').debug(traceback.format_exc())
        logger('staff.dns').debug(
                "DNS response dispatcher for %a terminated, cleaning up", dst)
        for _, w in waiters.items():
            w.set_exception(exc)


def gen_dns_id(id_map):
    i = random.randint(0, 65535)
    while i in id_map:
        i = random.randint(0, 65535)
    return i
