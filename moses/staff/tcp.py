import asyncio
import ctypes
import socket
import traceback
from .. import socks
from .. import io
from ..log import logger


SO_ORIGINAL_DST = 80


class sin_addr(ctypes.Structure):
    _fields_ = [
        ('s_addr', ctypes.c_uint32)
    ]


class sockaddr_in(ctypes.Structure):
    _fields_ = [
        ('sin_family', ctypes.c_int16),
        ('sin_port',   ctypes.c_uint16),
        ('sin_addr',   sin_addr),
        ('sin_zero',   ctypes.c_uint8 * 8)
    ]


@asyncio.coroutine
def tcp_server_cb(reader, writer, proxy, bs):
    sock = writer.get_extra_info('socket')

    orig_dst_buf = \
            sock.getsockopt(
                    socket.SOL_IP, SO_ORIGINAL_DST, ctypes.sizeof(sockaddr_in))
    orig_dst = sockaddr_in.from_buffer_copy(orig_dst_buf)

    logger('staff.tcp').debug(
            'orig_dst = (%d, %d)',
            orig_dst.sin_addr.s_addr, orig_dst.sin_port)

    try:
        proxy_reader, proxy_writer = yield from socks.open_connection(
                proxy, 0x01, (orig_dst.sin_addr.s_addr, orig_dst.sin_port))
    except:
        logger('staff.tcp').debug(traceback.format_exc())
        writer.close()
        return

    yield from io.do_streaming(reader, writer, proxy_reader, proxy_writer, bs)
    proxy_writer.close()
    writer.close()
