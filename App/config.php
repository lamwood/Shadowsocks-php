<?php
//服务器端配置
$SERVER = [
    //服务器IP地址,0.0.0.0表示监听服务器所有网卡
    'host' => '0.0.0.0',
    //加密算法
    'method' => 'aes-256-gcm',
    //密码
    'password' => '123456',
    //服务器SS端口号
    'port' => 8080,
    //启动的进程数
    'process' => 2
];
//中继端配置
$RELAY = [
    //服务器IP地址,
    'server' => '127.0.0.1', //
    //服务器SS端口号
    'port' => 8080,
    //中继机IP地址,0.0.0.0表示监听客户端机器所有网卡
    'relay_host' => '0.0.0.0',
    //中继端监听端口
    'relay_port' => 1080,
    //启动的进程数
    'process' => 2
];
//客户端配置
$CLIENT = [
    //服务器IP地址,
    'server' => '127.0.0.1',
    //服务器SS端口号
    'port' => 8080,
    //客户端IP地址,0.0.0.0表示监听客户端机器所有网卡
    'local_host' => '127.0.0.1',
    //客户端监听端口
    'local_port' => 1080,
    //加密算法
    'method' => 'aes-256-gcm',
    //密码
    'password' => '123456',
    //启动的进程数
    'process' => 2
];

