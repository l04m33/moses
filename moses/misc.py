import ssl


def parse_ip_port(addr_str):
    last_col = addr_str.rfind(':')
    return (addr_str[0:last_col], int(addr_str[last_col+1:]))


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
