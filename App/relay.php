<?php
/**
 * shadowsocks 中继端
 * @author Wood Lin <frozen2way@gmail.com>
 */

use Workerman\Worker;
use Workerman\Connection\AsyncTcpConnection;
use Workerman\Autoloader;

//自动加载
require_once ROOT_PATH.'/Workerman/Autoloader.php';
require_once APP_PATH.'/config.php';
Autoloader::setRootPath(__DIR__);

// 状态相关
define('STAGE_INIT', 0);
define('STAGE_ADDR', 1);
define('STAGE_UDP_ASSOC', 2);
define('STAGE_DNS', 3);
define('STAGE_CONNECTING', 4);
define('STAGE_STREAM', 5);
define('STAGE_DESTROYED', -1);

//将屏幕打印输出到Worker::$stdoutFile指定的文件中
Worker::$stdoutFile = ROOT_PATH.'/shadowsocks.log';
//设置所有连接的默认应用层发送缓冲区大小2M
AsyncTcpConnection::$defaultMaxSendBufferSize = 2 * 1024 * 1024;
//初始化worker，监听$RELAY_PORT端口
$Worker = new Worker('tcp://'.$RELAY['relay_host'].':'.$RELAY['relay_port']);
//进程数量
$Worker->count = $RELAY['process'];
//名称
$Worker->name = 'Shadowsock-relay';
//当客户端连上来时
$Worker->onConnect = function($connection){
    //设置当前连接的状态为STAGE_INIT，初始状态
    $connection->stage = STAGE_INIT;
};
//当客户端发来消息时
$Worker->onMessage = function($connection, $buffer)use($RELAY){
    //判断当前的连接状态
    switch($connection->stage){
        case STAGE_INIT:
        case STAGE_ADDR:
            $connection->stage = STAGE_CONNECTING;
            $address = 'tcp://'.$RELAY['server'].':'.$RELAY['port'];
            $remote_connection = new AsyncTcpConnection($address);
            //
            $connection->pipe($remote_connection);
            $remote_connection->pipe($connection);
            //执行远程连接
            $remote_connection->connect();
            //改变当前连接的状态为STAGE_STREAM，即开始转发数据流
            $connection->stage = STAGE_STREAM;
            $remote_connection->send($buffer);
            break;
        default:
            break;
    }
};

//如果不是在根目录启动，则运行runAll方法
if(!defined('GLOBAL_START')){
    Worker::runAll();
}
