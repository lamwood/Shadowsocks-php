<?php
/**
 * @author Wood Lin <frozen2way@gmail.com>
 * Shadowsocks PHP版本
 * php start.php start|stop|restart|reload
 */
use Workerman\Worker;

//检查扩展
if(!extension_loaded('pcntl')){
    #exit('Please install pcntl extension.');
}elseif(!extension_loaded('posix')){
    #exit('Please install posix extension.');
}
//标记是全局启动
define('GLOBAL_START', 1);
define('ROOT_PATH', __DIR__);
define('APP_PATH', ROOT_PATH.'/App');
//
//加载shadowsocks启动文件
#require_once APP_PATH.'/local.php'; //启动shadowsocks客户端
#require_once APP_PATH.'/relay.php'; //启动shadowsocks中继端
require_once APP_PATH.'/server.php';//启动shadowsocks服务端
//运行
Worker::runAll();
