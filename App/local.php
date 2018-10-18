<?php
/**
 * @author Wood Lin <frozen2way@gmail.com>
 * Shadowsock 客户端程序
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
// 命令
define('CMD_CONNECT', 1);
define('CMD_BIND', 2);
define('CMD_UDP_ASSOCIATE', 3);

//将屏幕打印输出到Worker::$stdoutFile指定的文件中
Worker::$stdoutFile = ROOT_PATH.'/shadowsocks.log';
//设置所有连接的默认应用层发送缓冲区大小2M
AsyncTcpConnection::$defaultMaxSendBufferSize = 2 * 1024 * 1024;
//初始化worker，监听$LOCAL_PORT端口
$Worker = new Worker('tcp://'.$CLIENT['local_host'].':'.$CLIENT['local_port']);
//进程数量
$Worker->count = $CLIENT['process'];
//名称
$Worker->name = 'Shadowsock-local';
//当客户端连上来时
$Worker->onConnect = function($connection)use($CLIENT){
    //if(preg_match('/^(100|42)\.[0-9]{1,3}\./', $connection->getRemoteIp())){
        //return $connection->close();
    //}
    //echo '['.date('Y-m-d H:i:s').'] '.$connection->getRemoteIp()."\n";
    //设置当前连接的状态为STAGE_INIT，初始状态
    $connection->stage = STAGE_INIT;
    //初始化加密类
    $connection->encryptor = new Encryptor($CLIENT['password'], $CLIENT['method']);
};
//当客户端发来消息时
$Worker->onMessage = function($connection, $buffer)use($CLIENT){
    //判断当前的连接状态
    switch($connection->stage){
        case STAGE_INIT:
            //与客户端建立SOCKS5连接
            $connection->send("\x05\x00");
            $connection->stage = STAGE_ADDR;
            return;
        case STAGE_ADDR:
            $cmd = ord($buffer[1]);
            //仅处理客户端的TCP连接请求
            if($cmd != CMD_CONNECT){
                echo '['.date('Y-m-d H:i:s').']unsupport cmd'."\n";
                $connection->send("\x05\x07\x00\x01");
                return $connection->close();
            }
            $connection->stage = STAGE_CONNECTING;
            //
            $buf_replies = "\x05\x00\x00\x01\x00\x00\x00\x00".pack('n', $CLIENT['local_port']);
            $connection->send($buf_replies);
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
            //远程连接发来消息时，进行解密，转发给客户端
            $remote_connection->onMessage = function($remote_connection, $buffer){
                $remote_connection->opposite->send($remote_connection->opposite->encryptor->decrypt($buffer));
            };
            //远程连接断开时，则断开客户端的连接
            $remote_connection->onClose = function($remote_connection){
                //关闭对端
                $remote_connection->opposite->close();
                $remote_connection->opposite = null;
            };
            //远程连接发生错误时（一般是建立连接失败错误），关闭客户端的连接
            $remote_connection->onError = function($remote_connection, $code, $msg)use($address){
                echo '['.date('Y-m-d H:i:s').']remote_connection '.$address.' error code:'.$code.' msg:'.$msg."\n";
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
            //当客户端发来数据时，加密数据，并发给远程服务端
            $connection->onMessage = function($connection, $data){
                $connection->opposite->send($connection->encryptor->encrypt($data));
            };
            //当客户端关闭连接时，关闭远程服务端的连接
            $connection->onClose = function($connection){
                $connection->opposite->close();
                $connection->opposite = null;
            };
            //当客户端连接上有错误时，关闭远程服务端连接
            $connection->onError = function($connection, $code, $msg){
                echo '['.date('Y-m-d H:i:s').'] connection err code:'.$code.' msg:'.$msg."\n";
                $connection->close();
                if(isset($connection->opposite)){
                    $connection->opposite->close();
                }
            };
            //执行远程连接
            $remote_connection->connect();
            //改变当前连接的状态为STAGE_STREAM，即开始转发数据流
            $connection->stage = STAGE_STREAM;
            //转发首个数据包，包含由客户端封装的目标地址，端口号等信息
            $buffer = substr($buffer, 3);
            $buffer = $connection->encryptor->encrypt($buffer);
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
