<?php
/**
 * Shadowsocks PHP版本
 * php start.php start
 */
use Workerman\Worker;

//检查扩展
if(!extension_loaded('pcntl')){
    exit('Please install pcntl extension.');
}elseif(!extension_loaded('posix')){
    exit('Please install posix extension.');
}
//标记是全局启动
define('GLOBAL_START', 1);
define('ROOT_PATH', __DIR__);
define('APP_PATH', ROOT_PATH.'/App');
//
require_once __DIR__.'/Workerman/Autoloader.php';
//加载shadowsocks启动文件
require_once APP_PATH.'/server.php';//服务端
#require_once APP_PATH.'/local.php';//客户端
//运行
Worker::runAll();
