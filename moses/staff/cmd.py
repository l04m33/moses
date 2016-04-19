import argparse
import asyncio
import functools
import logging
from .. import misc
from .. import defaults
from . import dns
from . import tcp
from ..log import logger


def create_tcp_server(loop, addr, port, proxy, backlog, bs):
    logger('staff').info('TCP server listening on %s:%d', addr, port)
    cb = functools.partial(tcp.tcp_server_cb, proxy=proxy, bs=bs)
    srv_op = asyncio.start_server(
            cb, host=addr, port=port,
            reuse_address=True, backlog=backlog, loop=loop)
    return loop.run_until_complete(srv_op)


def create_udp_server(
        loop, addr, port, proxy, dns_servers, timeout, dns_cache):
    logger('staff').info('UDP server listening on %s:%d', addr, port)
    # The reuse_address argument for create_datagram_endpoint does not exist
    # before Python 3.4.4, so we don't use it for better compatibility.
    ep_op = loop.create_datagram_endpoint(
            lambda: dns.DNSRelayProtocol(
                proxy, dns_servers, timeout, dns_cache),
            local_addr=(addr, port))
    return loop.run_until_complete(ep_op)


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('-t', '--tcp-port',
            help='The TCP port to listen on (default: {})'.format(
                defaults.STAFF_TCP_PORT),
            default=defaults.STAFF_TCP_PORT,
            type=int)
    parser.add_argument('-u', '--udp-port',
            help='The UDP port to listen on (default: {})'.format(
                defaults.STAFF_UDP_PORT),
            default=defaults.STAFF_UDP_PORT,
            type=int)
    parser.add_argument('-p', '--proxy',
            metavar='<ADDRESS>:<PORT>',
            help='Moses proxy address (default: {})'.format(
                defaults.STAFF_PROXY),
            default=defaults.STAFF_PROXY,
            type=str)
    parser.add_argument('-d', '--dns',
            metavar='<ADDRESS>:<PORT>[,<ADDRESS>:<PORT>...]',
            help='Name server address (default: {})'.format(
                defaults.STAFF_DNS),
            default=defaults.STAFF_DNS,
            type=str)
    parser.add_argument('--block-size',
            help='Block size for data streaming, in bytes (default: {})'.format(
                defaults.BLOCK_SIZE),
            default=defaults.BLOCK_SIZE,
            type=int)
    parser.add_argument('--dns-timeout',
            help='Timeout for DNS requests, in seconds (default: {})'.format(
                defaults.STAFF_DNS_TIMEOUT),
            default=defaults.STAFF_DNS_TIMEOUT,
            type=float)
    parser.add_argument('--dns-cache-size',
            help='Max size for the local DNS cache. Set to zero to disable ' +
                 'caching. EXPERIMENTAL (default: {})'.format(
                     defaults.STAFF_DNS_CACHE_SIZE),
            default=defaults.STAFF_DNS_CACHE_SIZE,
            type=int)
    parser.add_argument('--backlog',
            help='Backlog for the listening socket (default: {})'.format(
                defaults.BACKLOG),
            default=defaults.BACKLOG,
            type=int)
    parser.add_argument('--loglevel',
            help='Log level (default: {})'.format(defaults.LOG_LEVEL),
            default=defaults.LOG_LEVEL,
            type=str,
            choices=[
                'critical', 'fatal', 'error',
                'warning', 'info', 'debug',
                ])

    return parser.parse_args()


def parse_dns_servers(dns_str):
    return [misc.parse_ip_port(d) for d in dns_str.split(',')]


def main():
    args = parse_arguments()
    logging.basicConfig(
            level=args.loglevel.upper(),
            format='%(asctime)s:%(levelname)s:%(name)s:%(message)s')

    loop = asyncio.get_event_loop()

    if args.dns_cache_size != 0:
        dns_cache = dns.DNSCache(max_size=args.dns_cache_size)
    else:
        dns_cache = None

    transport, _protocol = \
            create_udp_server(
                    loop, '127.0.0.1', args.udp_port,
                    misc.parse_ip_port(args.proxy),
                    parse_dns_servers(args.dns),
                    args.dns_timeout,
                    dns_cache)

    server = \
            create_tcp_server(
                    loop, '127.0.0.1', args.tcp_port,
                    misc.parse_ip_port(args.proxy),
                    args.backlog,
                    args.block_size)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    transport.close()
