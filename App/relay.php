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

//初始化worker，监听$LOCAL_PORT端口
$Worker = new Worker('tcp://'.$CLIENT['local_host'].':'.$CLIENT['local_port']);
//进程数量
$Worker->count = $CLIENT['process'];
//名称
$Worker->name = 'Shadowsock-relay';
//当客户端连上来时
$Worker->onConnect = function($connection)use($CLIENT){
    // 设置当前连接的应用层发送缓冲区大小为5M字节
    $connection->maxSendBufferSize = 1024 * 1024 * 5;
    //设置当前连接的状态为STAGE_INIT，初始状态
    $connection->stage = STAGE_INIT;
};
//当客户端发来消息时
$Worker->onMessage = function($connection, $buffer)use($CLIENT){
    //判断当前的连接状态
    switch($connection->stage){
        case STAGE_INIT:
        case STAGE_ADDR:
            $connection->stage = STAGE_CONNECTING;
            $address = 'tcp://'.$CLIENT['server'].':'.$CLIENT['port'];
            $remote_connection = new AsyncTcpConnection($address);
            $connection->opposite = $remote_connection;
            $remote_connection->opposite = $connection;
            //流量控制
            $remote_connection->onBufferFull = function($remote_connection){
                $remote_connection->opposite->pauseRecv();
            };
            $remote_connection->onBufferDrain = function($remote_connection){
                $remote_connection->opposite->resumeRecv();
            };
            //远程连接发来消息时，转发给客户端
            $remote_connection->onMessage = function($remote_connection, $buffer){
                $remote_connection->opposite->send($buffer);
            };
            //远程连接断开时，则断开客户端的连接
            $remote_connection->onClose = function($remote_connection){
                //关闭对端
                $remote_connection->opposite->close();
                $remote_connection->opposite = null;
            };
            //远程连接发生错误时（一般是建立连接失败错误），关闭客户端的连接
            $remote_connection->onError = function($remote_connection, $code, $msg)use($address){
                $remote_connection->close();
                if($remote_connection->opposite){
                    $remote_connection->opposite->close();
                }
            };
            //流量控制
            $connection->onBufferFull = function($connection){
                $connection->opposite->pauseRecv();
            };
            $connection->onBufferDrain = function($connection){
                $connection->opposite->resumeRecv();
            };
            //当客户端发来数据时，并发给远程服务端
            $connection->onMessage = function($connection, $data){
                $connection->opposite->send($data);
            };
            //当客户端关闭连接时，关闭远程服务端的连接
            $connection->onClose = function($connection){
                $connection->opposite->close();
                $connection->opposite = null;
            };
            //当客户端连接上有错误时，关闭远程服务端连接
            $connection->onError = function($connection, $code, $msg){
                $connection->close();
                if(isset($connection->opposite)){
                    $connection->opposite->close();
                }
            };
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
