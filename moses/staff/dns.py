import asyncio
import collections
import struct
import functools
import random
import traceback
from .. import socks
from ..log import logger


class DNSRelayConnection:
    def __init__(self, reader, writer, dst, waiters=None, id_map=None):
        self.reader = reader
        self.writer = writer
        self.dst = dst
        if waiters is None:
            self.waiters = {}
        else:
            self.waiters = waiters
        if id_map is None:
            self.id_map = {}
        else:
            self.id_map = id_map

    @classmethod
    @asyncio.coroutine
    def new(cls, dst, proxy):
        conn_op = asyncio.async(socks.open_connection(proxy, 0x81, dst))
        logger('staff.dns').debug('Creating DNS relay connection %a', dst)
        reader, writer = yield from asyncio.wait_for(conn_op, None)
        new_conn = cls(reader, writer, dst)
        dispatch_op = asyncio.async(new_conn.resp_dispatcher())
        dispatch_op.add_done_callback(new_conn.resp_dispatcher_done)
        logger('staff.dns').debug('Done creating DNS relay connection %a', dst)
        return new_conn

    @classmethod
    @asyncio.coroutine
    def get(cls, dst, proxy):
        if not hasattr(cls, 'conn_pool'):
            cls.conn_pool = {}

        conn = cls.conn_pool.get(dst)

        if conn is None:
            # No existing connection found. Create a new one.
            cls.conn_pool[dst] = asyncio.Future()
            try:
                conn = yield from cls.new(dst, proxy)
            except Exception as exc:
                cls.clean_up_bad_conn(dst, exc)
                raise
        elif isinstance(conn, asyncio.Future):
            # Connecting or busy, we wait for the connection
            logger('staff.dns').debug('Waiting for DNS relay connection %a', dst)
            conn = yield from asyncio.wait_for(conn, None)
            while isinstance(cls.conn_pool[dst], asyncio.Future):
                logger('staff.dns').debug('Connection %a is busy. Keep waiting.', dst)
                conn = yield from asyncio.wait_for(cls.conn_pool[dst], None)
            logger('staff.dns').debug('Acquired DNS relay connection %a', dst)
            cls.conn_pool[dst] = asyncio.Future()
        else:
            cls.conn_pool[dst] = asyncio.Future()

        return conn

    @classmethod
    def clean_up_bad_conn(cls, dst, exc):
        logger('staff.dns').debug(
                'Lost the connection %s:%d to Moses server, cleaning up',
                dst[0], dst[1])
        cls.conn_pool[dst].set_exception(exc)
        # in case there's no coroutine waiting for this future,
        # prevent asyncio from complaining about never retrieved exceptions
        cls.conn_pool[dst].exception()
        del cls.conn_pool[dst]

    def put(self):
        waiter = self.conn_pool[self.dst]
        self.conn_pool[self.dst] = self
        waiter.set_result(self.conn_pool[self.dst])

    @asyncio.coroutine
    def send_msg(self, msg, src):
        dns_id, = struct.unpack_from('>H', msg)
        logger('staff.dns').debug('dns_id = %d', dns_id)

        waiter_key = (src, dns_id)
        old_waiter = self.waiters.get(waiter_key)
        if old_waiter is not None:
            logger('staff.dns').debug(
                    'Previous request from %r for ID %d is still pending, cancelling',
                    src, dns_id)
            old_waiter.cancel()
        dns_waiter = asyncio.Future()
        self.waiters[waiter_key] = dns_waiter

        relay_dns_id = self.gen_dns_id()
        self.id_map[relay_dns_id] = waiter_key
        logger('staff.dns').debug('relay_dns_id = %d', relay_dns_id)

        msg_len = struct.pack('>H', len(msg))
        self.writer.write(msg_len)
        self.writer.write(struct.pack('>H', relay_dns_id) + msg[2:])
        try:
            yield from self.writer.drain()
        except Exception as exc:
            self.clean_up_bad_conn(self.dst, exc)
            del self.waiters[waiter_key]
            del self.id_map[relay_dns_id]
            raise

        return (relay_dns_id, dns_waiter)

    @asyncio.coroutine
    def wait_for_reply(self, relay_dns_id, dns_waiter, timeout):
        waiter_key = self.id_map[relay_dns_id]
        src, dns_id = waiter_key

        try:
            resp_msg = yield from asyncio.wait_for(dns_waiter, timeout)
        except asyncio.TimeoutError:
            logger('staff.dns').debug(
                    'DNS request %d from %r timed out', dns_id, src)
            if self.waiters[waiter_key] == dns_waiter:
                del self.waiters[waiter_key]
            del self.id_map[relay_dns_id]
            raise
        except:
            del self.id_map[relay_dns_id]
            raise

        logger('staff.dns').debug('Got DNS reply for %a, dns_id = %d', src, dns_id)
        return resp_msg

    @asyncio.coroutine
    def resp_dispatcher(self):
        while True:
            msg_len_buf = yield from self.reader.readexactly(2)
            msg_len, = struct.unpack('>H', msg_len_buf)

            assert msg_len > 2

            msg = yield from self.reader.readexactly(msg_len)
            relay_dns_id, = struct.unpack_from('>H', msg)
            logger('staff.dns').debug('Got relayed DNS msg for ID %d', relay_dns_id)

            waiter_key = self.id_map.get(relay_dns_id)
            if waiter_key is not None:
                w = self.waiters.get(waiter_key)
                if isinstance(w, asyncio.Future):
                    del self.waiters[waiter_key]
                    w.set_result(msg)
                del self.id_map[relay_dns_id]
                logger('staff.dns').debug(
                        'Current id_map size: %d', len(self.id_map))

    def resp_dispatcher_done(self, fut):
        try:
            fut.result()
        except Exception as exc:
            logger('staff.dns').debug(traceback.format_exc())
            logger('staff.dns').debug(
                    "DNS response dispatcher for %a terminated, cleaning up",
                    self.dst)
            for _, w in self.waiters.items():
                w.set_exception(exc)

    def gen_dns_id(self):
        i = random.randint(0, 65535)
        while i in self.id_map:
            i = random.randint(0, 65535)
        return i


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

    relay_conn = yield from DNSRelayConnection.get(dst, proxy)
    relay_dns_id, dns_waiter = yield from relay_conn.send_msg(msg, src)
    logger('staff.dns').debug('UDP msg sent to %a', dst)
    logger('staff.dns').debug('Releasing DNS relay connection %a', dst)
    relay_conn.put()

    resp_msg = yield from \
            relay_conn.wait_for_reply(relay_dns_id, dns_waiter, timeout)
    transport.sendto(msg[:2] + resp_msg[2:], addr=src)


def forward_dns_msg_done(fut):
    try:
        fut.result()
    except:
        logger('staff.dns').debug(traceback.format_exc())

    logger('staff.dns').debug('forward_dns_msg_done')
