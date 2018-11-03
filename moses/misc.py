import sys
import asyncio
import ssl
import re
import moses.defaults as defaults


IP_PORT_RE = '''
    ^
    (
        ((([0-9]{1,3}\.){3}[0-9]{1,3})(:([0-9]{1,5}))?)               # ipv4[:port]
        |
        (([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})                    # ipv6 without port no.
        |
        (\[(([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})\]:([0-9]{1,5})) # ipv6 with port no.
        |
        (([^:]+)(:([0-9]{1,5}))?)                                     # domain[:port]
        |
        (:([0-9]{1,5}))                                               # :port
    )
    $
    '''

def parse_ip_port(addr_str):
    m = re.match(IP_PORT_RE, addr_str, re.VERBOSE)
    if m is None:
        raise RuntimeError('Bad address: {}'.format(addr_str))

    if m.group(2) is not None:
        # ipv4[:port]
        addr = m.group(3)
        if m.group(6) is not None:
            port = int(m.group(6))
        else:
            port = defaults.BINDING_PORT
    elif m.group(7) is not None:
        # ipv6 without port no.
        addr = m.group(7)
        port = defaults.BINDING_PORT
    elif m.group(9) is not None:
        # ipv6 with port no.
        addr = m.group(10)
        port = int(m.group(12))
    elif m.group(13) is not None:
        # domain[:port]
        addr = m.group(14)
        if m.group(16) is not None:
            port = int(m.group(16))
        else:
            port = defaults.BINDING_PORT
    elif m.group(17) is not None:
        # :port
        addr = ''
        port = int(m.group(18))

    return (addr, port)


def parse_keepalive_params(ka_str):
    params = tuple((int(n) for n in ka_str.split(',')))
    assert len(params) == 3
    return params


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


if sys.version_info < (3, 5):
    # The word 'async' became a keyword in later Python versions,
    # and would cause syntax errors if not quoted.
    ensure_future = getattr(asyncio, 'async')
else:
    ensure_future = asyncio.ensure_future
