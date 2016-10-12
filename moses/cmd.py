import argparse
import ssl
import asyncio
import logging
from .server import server_main
from .client import client_main
from . import defaults


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
            help='IP & port to bind (default: {})'.format(
                defaults.BINDING_ADDRESS),
            default=defaults.BINDING_ADDRESS,
            type=str)
    common_group.add_argument('-n', '--no-tls',
            help='Do not use TLS encryption',
            action='store_true')
    common_group.add_argument('-l', '--local-cert',
            help='Local SSL certificates (default: {})'.format(
                defaults.LOCAL_CERT_FILE),
            default=defaults.LOCAL_CERT_FILE,
            type=str)
    common_group.add_argument('-r', '--remote-cert',
            help='Remote SSL certificates (default: {})'.format(
                defaults.REMOTE_CERT_FILE),
            default=defaults.REMOTE_CERT_FILE,
            type=str)
    common_group.add_argument('-e', '--ciphers',
            help='Ciphers to use for encryption. '
                 'Run `openssl ciphers` to see available ciphers',
            type=str)
    common_group.add_argument('--backlog',
            help='Backlog for the listening socket (default: {})'.format(
                defaults.BACKLOG),
            default=defaults.BACKLOG,
            type=int)
    common_group.add_argument('--loglevel',
            help='Log level (default: {})'.format(defaults.LOG_LEVEL),
            default=defaults.LOG_LEVEL,
            type=str,
            choices=[
                'critical', 'fatal', 'error',
                'warning', 'info', 'debug',
                ])
    common_group.add_argument('--block-size',
            help='Block size for data streaming, in bytes (default: {})'.format(
                defaults.BLOCK_SIZE),
            default=defaults.BLOCK_SIZE,
            type=int)
    common_group.add_argument('-k', '--keepalive',
            help='TCP keepalive parameters, '
                 'in the form of <keepalive_time>,<keepalive_probes>,<keepalive_intvl>. '
                 'See `man 7 tcp` for details (default: keepalive disabled)',
            type=str)

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
