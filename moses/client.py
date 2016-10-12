import sys
import asyncio
import functools
from . import defaults
from . import io
from . import misc
from .log import logger


@asyncio.coroutine
def client_connection_cb(reader, writer, params):
    server_addr = params['server_addr']
    bs = params.get('bs', defaults.BLOCK_SIZE)
    ssl_ctx = params.get('ssl_ctx', None)
    keepalive = params.get('keepalive', None)

    remote_rw = yield from io.do_connect(
            server_addr[0], server_addr[1], ssl=ssl_ctx, keepalive=keepalive)
    if remote_rw is None:
        writer.close()
        return

    yield from io.do_streaming(reader, writer, remote_rw[0], remote_rw[1], bs)

    remote_rw[1].close()
    writer.close()


def client_main(loop, args):
    logger('client').info('Moses client listening at %s', args.bind)
    logger('client').info('Forwarding to %s', args.peer)

    if args.peer is None:
        logger('client').error('No peer (server) address provided')
        sys.exit(1)

    try:
        server_addr = misc.parse_ip_port(args.peer)
    except:
        logger('client').error('Bad peer address: %s', args.peer)
        sys.exit(1)

    if args.no_tls:
        logger('client').warning('Connections to the server are NOT encrypted')
        ssl_ctx = None
    else:
        ssl_ctx = misc.build_ssl_ctx(
                args.local_cert, args.remote_cert, args.ciphers)

    if args.keepalive is None:
        keepalive = None
    else:
        try:
            keepalive = misc.parse_keepalive_params(args.keepalive)
        except:
            logger('client').error('Bad keepalive parameters: %s', args.keepalive)
            sys.exit(1)

    params = {
        'server_addr': server_addr,
        'bs': args.block_size,
        'ssl_ctx': ssl_ctx,
        'keepalive': keepalive,
    }
    cb = functools.partial(client_connection_cb, params=params)

    local_ip, local_port = misc.parse_ip_port(args.bind)
    starter = asyncio.start_server(cb, local_ip, local_port,
            backlog=args.backlog,
            reuse_address=True,
            loop=loop)
    return loop.run_until_complete(starter)
