<?php
/**
 * php7 协议类
 * @author Wood <wood@example.com>
 */
class Protocol{
    //
    protected $_protocol;
    protected static $_protocolSupported = [
        'origin',
    ];
    //
    public function __construct($protocol = 'origin'){
        switch($protocol){
            case 'origin':
                $this->_protocol = new OriginProtocol();
                break;
            default :
                $this->_protocol = new OriginProtocol();
                break;
        }
    }
    //客户端发送到服务端数据加密前
    public function ClientPreEncrypt($plaindata){
        return $this->_protocol->ClientPreEncrypt($plaindata);
    }
    //客户端收到服务端数据解密后
    public function ClientPostDecrypt($plaindata){
        return $this->_protocol->ClientPostDecrypt($plaindata);
    }
    //服务端发送到客户端数据加密前
    public function ServerPreEncrypt($plaindata){
        return $this->_protocol->ServerPreEncrypt($plaindata);
    }
    //服务端收到客户端数据解密后
    public function ServerPostDecrypt($plaindata){
        return $this->_protocol->ServerPostDecrypt($plaindata);
    }
}
//原生协议
class OriginProtocol{
    //
    public function __construct(){}
    //客户端发送到服务端数据加密前
    public function ClientPreEncrypt($plaindata){
        return $plaindata;
    }
    //客户端收到服务端数据解密后
    public function ClientPostDecrypt($plaindata){
        return $plaindata;
    }
    //服务端发送到客户端数据加密前
    public function ServerPreEncrypt($plaindata){
        return $plaindata;
    }
    //服务端收到客户端数据解密后
    public function ServerPostDecrypt($plaindata){
        return $plaindata;
    }
}