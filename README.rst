Moses
#####

Moses 是一个使用加密连接的 Socks5 代理，原理与 `ShadowSocks`_ 一致，
不过加密方法换成了 TLS, 支持服务端、客户端双向验证，更安全，不过连接
速度也更慢。

.. _ShadowSocks: https://shadowsocks.org/

安裝
####

.. code-block:: text

    ❯ pip install moses

或者使用最新代码：

.. code-block:: text

    ❯ git clone https://github.com/l04m33/moses.git
    ❯ pip install ./moses

使用方法
########

.. code-block:: text

    ❯ moses -h
    usage: moses [-h] (-c | -s) [-b <ADDRESS>:<PORT>] [-n] [-l LOCAL_CERT]
                 [-r REMOTE_CERT] [-e CIPHERS] [--backlog BACKLOG]
                 [--loglevel {critical,fatal,error,warning,info,debug}]
                 [--block-size BLOCK_SIZE] [-k KEEPALIVE] [-p <ADDRESS>:<PORT>]
                 [-f <ADDRESS>:<PORT>]

    optional arguments:
      -h, --help            show this help message and exit

    Common Options:
      -c, --client          Client mode
      -s, --server          Server mode
      -b <ADDRESS>:<PORT>, --bind <ADDRESS>:<PORT>
                            IP & port to bind (default: :1080)
      -n, --no-tls          Do not use TLS encryption
      -l LOCAL_CERT, --local-cert LOCAL_CERT
                            Local SSL certificates (default: ./local.pem)
      -r REMOTE_CERT, --remote-cert REMOTE_CERT
                            Remote SSL certificates (default: ./remote.pem)
      -e CIPHERS, --ciphers CIPHERS
                            Ciphers to use for encryption. Run `openssl ciphers`
                            to see available ciphers
      --backlog BACKLOG     Backlog for the listening socket (default: 128)
      --loglevel {critical,fatal,error,warning,info,debug}
                            Log level (default: info)
      --block-size BLOCK_SIZE
                            Block size for data streaming, in bytes (default:
                            2048)
      -k KEEPALIVE, --keepalive KEEPALIVE
                            TCP keepalive parameters, in the form of
                            <keepalive_time>,<keepalive_probes>,<keepalive_intvl>.
                            See `man 7 tcp` for details (default: keepalive
                            disabled)

    Client Options:
      -p <ADDRESS>:<PORT>, --peer <ADDRESS>:<PORT>
                            Peer (server) address

    Server Options:
      -f <ADDRESS>:<PORT>, --forward <ADDRESS>:<PORT>
                            Simply forward all connections to the given address

Socks5 代理
###########

启动服务器：

.. code-block:: text

    ❯ moses -s -b some.server.addr.ess:32000 \
            -l server_key.pem -r client_cert.pem

启动客户端：

.. code-block:: text

    ❯ moses -c -b 127.0.0.1:1080 -p some.server.addr.ess:32000 \
            -l client_key.pem -r server_cert.pem

转发 HTTP 代理
##############

Moses 本身没有实现 HTTP 代理，不过你可以用 Moses 将 HTTP 代理请求转
发到其他 HTTP 代理程序（例如 Privoxy_ ）上。假设你的服务器在 8118 端
口上配置了一个 Privoxy 实例，这样启动 Moses 服务器即可：

.. code-block:: text

    ❯ moses -s -b some.server.addr.ess:32000 \
            -f 127.0.0.1:8118 \
            -l server_key.pem -r client_cert.pem

.. _Privoxy: http://www.privoxy.org/

Linux 下的全局透明代理
######################

``staff`` 是一个透明代理脚本，通过与 ``moses`` 配合可以自动转发
所有 DNS 请求和 TCP 连接， poor man's VPN :)

使用方法（假设 Moses 客户端运行在 127.0.0.1:1080 上）：

.. code-block:: text

    ❯ staff -p 127.0.0.1:1080

然后用 iptables 添加这三条规则（当然 eth0 要替换成你自己的网络接口）：

.. code-block:: text

    ❯ iptables -t nat -I OUTPUT -o eth0 -p udp --dport 53  -j DNAT --to 127.0.0.1:32000
    ❯ iptables -t nat -I OUTPUT -o eth0 -p tcp --dport 80  -j DNAT --to 127.0.0.1:32000
    ❯ iptables -t nat -I OUTPUT -o eth0 -p tcp --dport 443 -j DNAT --to 127.0.0.1:32000

这样所有 DNS 请求和目标端口是 80、443 的 TCP 连接都会走 Moses 代理。

你也可以更进一步，用 geoip 规则忽略某墙国的 IP （需要安装 `xtables-addons`_ ）：

.. code-block:: text

    ❯ iptables -t nat -I OUTPUT -o eth0 -p tcp -m geoip ! --dst-cc CN -j DNAT --to 127.0.0.1:32000

要查看其他选项的用法，执行 ``staff -h`` .

.. _xtables-addons: http://xtables-addons.sourceforge.net/

License
#######

MIT.
