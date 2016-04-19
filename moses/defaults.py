BINDING_ADDRESS = ':1080'       # <ADDRESS>:<PORT>
LOCAL_CERT_FILE = './local.pem'
REMOTE_CERT_FILE = './remote.pem'
BACKLOG = 128
LOG_LEVEL = 'info'
BLOCK_SIZE = 2048       # in bytes


STAFF_TCP_PORT = 32000
STAFF_UDP_PORT = 32000
STAFF_PROXY = '127.0.0.1:1080'  # <ADDRESS>:<PORT>
STAFF_DNS = '8.8.8.8:53,8.8.4.4:53'
STAFF_DNS_TIMEOUT = 5.0         # in seconds
STAFF_DNS_CACHE_SIZE = 0        # max size for the local dns cache
