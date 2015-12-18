Moses
#####

Moses 是一个使用加密连接的 Socks5 代理，原理与 `ShadowSocks`_ 一致，
不过加密方法换成了 TLS, 支持服务端、客户端双向验证，更安全，不过连接
速度也更慢。

.. _ShadowSocks: https://shadowsocks.org/

使用方法
########

.. code-block:: txt

    ❯ ./moses.py -h
    usage: moses.py [-h] (-c | -s) [-b <ADDRESS>:<PORT>] [-l LOCAL_CERT]
                    [-r REMOTE_CERT] [--backlog BACKLOG]
                    [--loglevel {critical,fatal,error,warning,info,debug}]
                    [-p <ADDRESS>:<PORT>]

    optional arguments:
      -h, --help            show this help message and exit

    Common Options:
      -c, --client          Client mode
      -s, --server          Server mode
      -b <ADDRESS>:<PORT>, --bind <ADDRESS>:<PORT>
                            IP & port to bind (default: <all interfaces>:1080)
      -l LOCAL_CERT, --local-cert LOCAL_CERT
                            Local SSL certificates (default: ./local.pem)
      -r REMOTE_CERT, --remote-cert REMOTE_CERT
                            Remote SSL certificates (default: ./remote.pem)
      --backlog BACKLOG     Backlog for the listening socket (default: 128)
      --loglevel {critical,fatal,error,warning,info,debug}
                            Log level (default: info)

    Client Options:
      -p <ADDRESS>:<PORT>, --peer <ADDRESS>:<PORT>
                            Peer (server) address

启动服务器：

.. code-block:: sh

    ./moses.py -s -b some.server.addr.ess:32000 \
               -l server_key.pem -r client_cert.pem

启动客户端：

.. code-block:: sh

    ./moses.py -c -b 127.0.0.1:1080 -p some.server.addr.ess:32000 \
               -l client_key.pem -r server_cert.pem

License
#######

MIT.
