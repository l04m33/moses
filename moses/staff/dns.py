import asyncio
import collections
import struct
import ctypes
import functools
import random
import traceback
import time
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
        dns_id, = struct.unpack('>H', msg[:2])
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
            relay_dns_id, = struct.unpack('>H', msg[0:2])
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
    def __init__(self, proxy, dns_server, timeout, cache=None):
        self._proxy = proxy
        self._dns = dns_server
        self._timeout = timeout
        self._cache = cache

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data, addr):
        dns = random.choice(self._dns)
        fut = asyncio.async(
                forward_dns_msg(
                    data, addr, dns, self._cache, self._proxy,
                    self._transport, self._timeout))
        fut.add_done_callback(forward_dns_msg_done)

    def error_received(self, exc):
        logger('staff.dns').debug(exc)

    def connection_lost(self, exc):
        if exc is not None:
            logger('staff.dns').debug(exc)


class DNSMsgHeader(ctypes.BigEndianStructure):
    _fields_ = [
        ('id',          ctypes.c_uint16),
        ('flags',       ctypes.c_uint16),
        ('q_count',     ctypes.c_uint16),
        ('a_count',     ctypes.c_uint16),
        ('ns_count',    ctypes.c_uint16),
        ('ar_count',    ctypes.c_uint16),
    ]


def dns_pack_name(name):
    buf = bytearray()
    sub_names = name.split(b'.')
    for n in sub_names:
        n_len = len(n).to_bytes(1, 'big')
        buf.extend(n_len)
        buf.extend(n)
    return buf


def dns_parse_name(msg, off):
    name = bytearray()
    ptr_ended = False
    cur = off
    while msg[cur] > 0:
        if (msg[cur] & 0xc0) == 0xc0:
            if not ptr_ended:
                off = cur + 2
                ptr_ended = True
            ptr, = struct.unpack('>H', msg[cur:cur + 2])
            cur = ptr & ~0xc000
            continue
        name.extend(msg[cur + 1:cur + 1 + msg[cur]])
        name.extend(b'.')
        cur = cur + 1 + msg[cur]

    logger('staff.dns').debug('Parsed DNS name: %r', name)
    if ptr_ended:
        return (bytes(name), off)
    return (bytes(name), cur + 1)


def dns_parse_query(msg, off):
    name, off = dns_parse_name(msg, off)
    q_type, = struct.unpack('>H', msg[off:off + 2])
    q_class, = struct.unpack('>H', msg[off + 2:off + 4])
    return (name, q_type, q_class, off + 4)


def dns_parse_queries(n, msg, off):
    q_list = []
    while n > 0:
        name, q_type, q_class, off = dns_parse_query(msg, off)
        n -= 1
        if len(name) == 0:
            continue
        q_list.append((name, q_type, q_class))
    return (q_list, off)


def dns_parse_answer(msg, off):
    name, off = dns_parse_name(msg, off)

    a_type, = struct.unpack('>H', msg[off:off + 2])
    off += 2

    a_class, = struct.unpack('>H', msg[off:off + 2])
    off += 2

    ttl, = struct.unpack('>I', msg[off:off + 4])
    off += 4

    r_data_len, = struct.unpack('>H', msg[off:off + 2])
    off += 2

    r_data = msg[off:off + r_data_len]
    if a_type == 0x05:
        # It's a CNAME. Parse the full name.
        cname, _name_off = dns_parse_name(msg, off)
        r_data = dns_pack_name(cname)
    off += r_data_len

    return (name, a_type, a_class, ttl, r_data, off)


def dns_parse_answers(n, msg, off):
    a_list = []
    while n > 0:
        name, a_type, a_class, ttl, r_data, off = dns_parse_answer(msg, off)
        n -= 1
        if len(name) == 0:
            continue
        a_list.append((name, a_type, a_class, ttl, r_data))
    return a_list


class DNSCache:
    def __init__(self, max_size=None):
        self.max_size = max_size
        self.cache = {}

    def lookup(self, query):
        ents = self.cache.get(query)
        if ents is None:
            return []

        last_seen, ents = ents

        now = time.time()
        alive_ents = []
        for ent in ents:
            deadline, r_data = ent
            ttl = int(deadline - now)
            if ttl <= 0:
                logger('staff.dns').debug(
                        'Cached DNS record %r timed out.', query)
                continue
            alive_ents.append((deadline, r_data))

        if len(alive_ents) > 0:
            self.cache[query] = (last_seen, alive_ents)
            return alive_ents
        else:
            del self.cache[query]
            return []

    def _find_cached_records(self, name, q_class):
        ents = []
        # Try CNAME records first
        to_resolve = [ \
                (name, 0x05, q_class, deadline, r_data) \
                for deadline, r_data \
                in self.lookup((name, 0x05, q_class))]

        addr_found = False

        while len(to_resolve) > 0:
            logger('staff.dns').debug('to_resolve = %r', to_resolve)

            e = _name, q_type, _q_class, _deadline, r_data = to_resolve.pop(0)
            ents.append(e)

            if q_type == 0x01:
                continue

            cname, _off = dns_parse_name(r_data, 0)
            r = self.lookup((cname, 0x05, q_class))
            if len(r) > 0:
                to_resolve.extend([
                    (cname, 0x05, q_class, c_deadline, c_r_data)
                    for c_deadline, c_r_data in r])
            else:
                # Try A records
                r = self.lookup((cname, 0x01, q_class))
                if len(r) > 0:
                    addr_found = True
                to_resolve.extend([
                    (cname, 0x01, q_class, a_deadline, a_r_data)
                    for a_deadline, a_r_data in r])

        if len(ents) == 0:
            # No CNAME record found. Try A records
            r = self.lookup((name, 0x01, q_class))
            if len(r) > 0:
                addr_found = True
            ents.extend([
                (name, 0x01, q_class, a_deadline, a_r_data)
                for a_deadline, a_r_data in r])

        if not addr_found:
            # Can't resolve to the real address. Remove the whole chain
            for name, q_type, q_class, _deadline, _r_data in ents:
                try:
                    del self.cache[(name, q_type, q_class)]
                except KeyError:
                    pass
            ents = []

        logger('staff.dns').debug('ents = %r', ents)
        return ents

    def resolve(self, msg):
        body_off = ctypes.sizeof(DNSMsgHeader)
        header = DNSMsgHeader.from_buffer_copy(msg[:body_off])

        if header.flags & 0xf800:
            # Not a standard query. We don't touch these.
            return None
        if header.q_count != 1:
            # Multiple queries. we don't touch these either
            return None

        q_list, q_end_off = dns_parse_queries(header.q_count, msg, body_off)
        name, q_type, q_class = q_list[0]

        if q_type != 0x01 or q_class != 0x01 or len(name) == 0:
            # Not an ADDRESS query for INET. Let it through.
            return None

        ents = self._find_cached_records(name, q_class)
        if len(ents) == 0:
            return None

        # Response, Recursion Available
        header.flags |= 0x8080
        # No Authoritative Answer, Not Truncated, Reserved Zeros, Zero Response Code
        header.flags &= ~0x067f
        header.a_count = len(ents)

        now = time.time()
        buf = bytearray()
        buf.extend(header)
        buf.extend(msg[body_off:q_end_off])
        for name, a_type, a_class, deadline, r_data in ents:
            buf.extend(dns_pack_name(name))
            buf.extend(struct.pack(
                '>HHIH', a_type, a_class, int(deadline - now), len(r_data)))
            buf.extend(r_data)

        return buf

    def fill(self, resp_msg):
        body_off = ctypes.sizeof(DNSMsgHeader)
        header = DNSMsgHeader.from_buffer_copy(resp_msg[:body_off])

        if (not (header.flags & 0x8000)) or (header.flags & 0x7800):
            # Not a standard response. We don't touch these.
            return

        q_list, q_end_off = dns_parse_queries(header.q_count, resp_msg, body_off)

        a_list = dns_parse_answers(header.a_count, resp_msg, q_end_off)

        now = time.time()
        for name, a_type, a_class, ttl, r_data in a_list:
            if (a_type != 0x01 and a_type != 0x05) \
                    or a_class != 0x01 or ttl == 0:
                continue
            cached = self.cache.get((name, a_type, a_class))
            deadline = int(now + ttl)
            if cached is not None:
                if cached[0] != now:
                    del self.cache[(name, a_type, a_class)]
                cached[1].append((deadline, r_data))
            else:
                self.cache[(name, a_type, a_class)] = (now, [(deadline, r_data)])

        self.purge()

    def purge(self):
        cache_count = len(self.cache)
        logger('staff.dns').debug('Current DNS cache size: %d', cache_count)

        if self.max_size < 0:
            return

        if cache_count <= self.max_size:
            return

        now = time.time()
        for k, v in list(self.cache.items()):
            last_seen, ents = v
            for deadline, _r_data in ents:
                if int(deadline - now) <= 0:
                    logger('staff.dns').debug(
                            'Purging outdated record %r', k)
                    del self.cache[k]
                    break

        cache_count = len(self.cache)
        logger('staff.dns').debug('New DNS cache size: %d', cache_count)
        if cache_count <= self.max_size:
            return

        cache_items = list(self.cache.items())
        cache_items.sort(key=lambda i: i[1][0])     # sorting by last_seen
        for k, _v in cache_items[:cache_count - self.max_size]:
            del self.cache[k]
        logger('staff.dns').debug(
                'New DNS cache size after purging: %d', len(self.cache))


@asyncio.coroutine
def forward_dns_msg(msg, src, dst, dns_cache, proxy, transport, timeout):
    if len(msg) < 2:
        return

    if dns_cache is not None:
        cached_resp = dns_cache.resolve(msg)
        if cached_resp is not None:
            transport.sendto(cached_resp, addr=src)
            return

    relay_conn = yield from DNSRelayConnection.get(dst, proxy)
    relay_dns_id, dns_waiter = yield from relay_conn.send_msg(msg, src)
    logger('staff.dns').debug('UDP msg sent to %a', dst)
    logger('staff.dns').debug('Releasing DNS relay connection %a', dst)
    relay_conn.put()

    resp_msg = yield from \
            relay_conn.wait_for_reply(relay_dns_id, dns_waiter, timeout)

    if dns_cache is not None:
        dns_cache.fill(resp_msg)

    transport.sendto(msg[:2] + resp_msg[2:], addr=src)


def forward_dns_msg_done(fut):
    try:
        fut.result()
    except:
        logger('staff.dns').debug(traceback.format_exc())

    logger('staff.dns').debug('forward_dns_msg_done')
