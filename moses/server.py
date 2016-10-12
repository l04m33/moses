import sys
import functools
import asyncio
from . import misc
from . import client
from . import socks
from .log import logger


@asyncio.coroutine
def server_connection_cb(reader, writer, params):
    socks_req = yield from socks.handshake(reader, writer)
    if socks_req is None:
        writer.close()
        return

    cmd_handler = socks.supported_cmds[socks_req[0]]

    try:
        yield from cmd_handler(socks_req, reader, writer, params)
    finally:
        writer.close()


def server_main(loop, args):
    logger('server').info('Moses server listening at %s', args.bind)

    if args.keepalive is None:
        keepalive = None
    else:
        try:
            keepalive = misc.parse_keepalive_params(args.keepalive)
        except:
            logger('client').error('Bad keepalive parameters: %s', args.keepalive)
            sys.exit(1)

    if args.forward is not None:
        logger('server').info('Forwarding client connections to %s', args.forward)
        try:
            forward_addr = misc.parse_ip_port(args.forward)
        except:
            logger('server').error('Bad forwarding address: %s', args.forward)
            sys.exit(1)
        params = {
            'server_addr': forward_addr,
            'bs': args.block_size,
            'keepalive': keepalive,
        }
        cb = functools.partial(client.client_connection_cb, params=params)
    else:
        params = {
            'bs': args.block_size,
            'keepalive': keepalive,
        }
        cb = functools.partial(server_connection_cb, params=params)

    if args.no_tls:
        logger('server').warning('Connections from clients are NOT encrypted')
        ssl_ctx = None
    else:
        ssl_ctx = misc.build_ssl_ctx(
                args.local_cert, args.remote_cert, args.ciphers)

    local_ip, local_port = misc.parse_ip_port(args.bind)
    starter = asyncio.start_server(cb, local_ip, local_port,
            ssl=ssl_ctx,
            backlog=args.backlog,
            reuse_address=True,
            loop=loop)
    return loop.run_until_complete(starter)
