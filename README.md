###socks5原理
*介绍一下socks5协议： SOCKS协议位于传输层(TCP/UDP等)与应用层之间，其工作流程为:

1.client向proxy发出请求信息，用以协商传输方式
    
    * client连接proxy的第一个报文信息，进行认证机制协商
    +------------------------------------------+
    | version   |   nmethod  |    methods      |
    +-----------+------------+-----------------+
    | 1 bytes   |  1 bytes   | 1~255 bytes     +
    +------------------------------------------+
    *一般是 hex: 05 01 00 即：版本5，1种认证方式，NO AUTHENTICATION REQUIRED(无需认证 0x00)
    
2.proxy作出应答

    *proxy从methods字段中选中一个字节(一种认证机制)，并向Client发送响应报文
    +------------------------+
    |  version  |  methods   |
    +-----------+------------+
    |     1     |      1     |
    +------------------------+
    *一般是 hex: 05 00 即：版本5，无需认证
    
3.client接到应答后向proxy发送目的主机（destination server)的ip和port

    *认证机制相关的子协商完成后，client提交转发请求
    +----------------------------------------------------------+
    |  VER  |  CMD  |  RSV  |  ATYP  |  DST.ADDR  |  DST.PORT  |
    +-------+-------+-------+--------+------------+------------+
    |   1   |   1   | 0x00  |    1   |  variable  |      2     |
    +----------------------------------------------------------+
    *前3个一般是 hex: 05 01 00 地址类型可以是 * 0x01 IPv4地址 * 0x03 FQDN(全称域名) * 0x04 IPv6地址
    *对应不同的地址类型，地址信息格式也不同： * IPv4地址，这里是big-endian序的4字节数据 * FQDN，比如”www.nsfocus.net”，
    这里将是:0F 77 77 77 2E 6E 73 66 6F 63 75 73 2E 6E 65 74。注意，第一字节是长度域 * IPv6地址，这里是16字节数据。

4.proxy评估该目的主机地址，返回自身IP和port，此时C/P连接建立。

    *proxy评估来自client的转发请求并发送响应报文
    +----------------------------------------------------------------+
    |  VER  |     REP     |  RSV  |  ATYP  |  BND.ADDR  |  BND.PORT  |
    +-------+-------------+-------+--------+------------+------------+
    |   1   | 1(response) | 0x00  |    1   |  variable  |      2     |
    +----------------------------------------------------------------+
    *proxy可以靠DST.ADDR、DST.PORT、SOCKSCLIENT.ADDR、SOCKSCLIENT.PORT进行评估，以决定建立到转发目的地的
    *TCP连接还是拒绝转发。若允许则响应包的REP为0，非0则表示失败（拒绝转发或未能成功建立到转发目的地的TCP连接）

5.proxy与dst server连接

6.proxy将client发出的信息传到server，将server返回的信息转发到client。代理完成


# shadowsocks-php
A php port of shadowsocks based on Workerman

# Config
App/config.php

## Start

php start.php start -d

## Stop

php start.php stop

## Status

php start.php status
