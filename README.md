### PHP版shadowsocks
一个基于Wokerman的php版shadowsocks程序,拥有服务器端，中继端和客户端。  

### 配置
配置文件为App/config.php
根据自己的使用情景，做配置即可。

#### 仅支持以下的几种加密方式
* aes-128-cfb
* aes-192-cfb
* aes-256-cfb
* aes-128-gcm
* aes-192-gcm
* aes-256-gcm
* chacha20-poly1305
* chacha20-ietf-poly1305
* xchacha20-ietf-poly1305

其中chacha20-poly1305,chacha20-ietf-poly1305,xchacha20-ietf-poly1305需要php7.2.0以上版本，或者php 7.0.0版本以上加装sodium扩展

###程序运行

#### 启动

在项目目录下运行 `php start.php start -d`

#### 停止

在项目目录下运行 `php start.php stop`

#### 查看状态

在项目目录下运行 `php start.php status`


> 本项目参考自walkor/shadowsocks-php,如有侵权请联系本作者