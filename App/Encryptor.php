<?php
/**
 * php7 AES加密解密类
 */
class Encryptor{
    protected $_key;
    protected $_cipher;
    protected $_decipher;
    protected $_cipherIv;
    protected $_bytesToKeyResults = [];
    protected $_method;
    protected $_ivSent;
    protected static $_methodSupported = [
        'aes-128-cfb'=> [16, 16],
        'aes-192-cfb'=> [24, 16],
        'aes-256-cfb'=> [32, 16],
    ];
    //
    public function __construct($key, $method){
        $this->_key = $key;
        $this->_method = $method;
        if(!isset(self::$_methodSupported[$this->_method])){
            return null;
        }
        $iv_size = openssl_cipher_iv_length($this->_method); 
        $iv = openssl_random_pseudo_bytes($iv_size); 
        $this->_cipher = $this->getcipher($this->_key, $this->_method, 1, $iv);
    }
    //加密
    public function encrypt($buffer){
        $result = $this->_cipher->update($buffer);
        if ($this->_ivSent){
            return $result;
        }else{
            $this->_ivSent = true;
            return $this->_cipherIv.$result;
        }
    }
    //解密
    public function decrypt($buffer){
        if(!$this->_decipher){
            $decipher_iv_len = $this->getCipherLen($this->_method);
            $decipher_iv_len = $decipher_iv_len[1];
            $decipher_iv = substr($buffer, 0, $decipher_iv_len);
            $this->_decipher = $this->getCipher($this->_key, $this->_method, 0, $decipher_iv);
            $result = $this->_decipher->update(substr($buffer, $decipher_iv_len));
            return $result;
        }else{
            $result = $this->_decipher->update($buffer);
            return $result;
        }
    }
    //
    protected function getCipher($password, $method, $op, $iv){
        $method = strtolower($method);
        $m = $this->getCipherLen($method);
        if($m){
            $ref = $this->EVPBytesToKey($password, $m[0], $m[1]);
            $key = $ref[0];
            $iv_ = $ref[1];
            if($iv == null){
                $iv = $iv_;
            }
            if($op === 1){
                $this->_cipherIv = substr($iv, 0, $m[1]);
            }
            $iv = substr($iv, 0, $m[1]);
            if($op === 1){
                return new Encipher($method, $key, $iv);
            }else{
                return new Decipher($method, $key, $iv);
            }
        }
    }
    //
    protected function EVPBytesToKey($password, $key_len, $iv_len){
        $cache_key = "$password:$key_len:$iv_len";
        if(isset($this->_bytesToKeyResults[$cache_key])){
            return $this->_bytesToKeyResults[$cache_key];
        }
        $m = [];
        $i = 0;
        $count = 0;
        while ($count < $key_len + $iv_len){
            $data = $password;
            if ($i > 0){
                $data = $m[$i-1] . $password;
            }
            $d = md5($data, true);
            $m[] = $d;
            $count += strlen($d);
            $i += 1;
        }
        $ms = '';
        foreach($m as $buf){
           $ms .= $buf;
        }
        $key = substr($ms, 0, $key_len);
        $iv =  substr($ms, $key_len, $key_len + $iv_len);
        $this->_bytesToKeyResults[$cache_key] = [$key, $iv];
        return [$key, $iv];
    }
    //
    protected function getCipherLen($method){
        $method = strtolower($method);
        return isset(self::$_methodSupported[$method]) ? self::$_methodSupported[$method] : null;
    }
}
//
class Encipher{
    protected $_algorithm;
    protected $_key;
    protected $_iv;
    protected $_tail;
    protected $_ivLength;
    public function __construct($algorithm, $key, $iv){
        $this->_algorithm = $algorithm;
        $this->_key = $key;
        $this->_iv = $iv;
        $this->_ivLength = openssl_cipher_iv_length($algorithm);
    }
    //
    public function update($data){
        if(strlen($data) == 0){
            return '';
        } 
        $tl = strlen($this->_tail);
        if($tl){
            $data = $this->_tail . $data;
        }
        $b = openssl_encrypt($data, $this->_algorithm, $this->_key, OPENSSL_RAW_DATA, $this->_iv);
        $result = substr($b, $tl);
        $dataLength = strlen($data);
        $mod = $dataLength%$this->_ivLength;
        if($dataLength >= $this->_ivLength){
            $iPos = -($mod + $this->_ivLength);
            $this->_iv = substr($b, $iPos, $this->_ivLength);
        }
        $this->_tail = $mod != 0 ? substr($data, -$mod) : '';
        return $result;
    }
}
class Decipher extends Encipher{
    public function update($data){
        if(strlen($data) == 0){
            return '';
        }
        $tl = strlen($this->_tail);
        if($tl){
            $data = $this->_tail.$data;
        }
        $b = openssl_decrypt($data, $this->_algorithm, $this->_key, OPENSSL_RAW_DATA, $this->_iv);
        $result = substr($b, $tl);
        $dataLength = strlen($data);
        $mod = $dataLength%$this->_ivLength;
        if($dataLength >= $this->_ivLength){
            $iPos = -($mod + $this->_ivLength);
            $this->_iv = substr($data, $iPos, $this->_ivLength); 
        }
        $this->_tail = $mod != 0 ? substr($data, -$mod) : '';
        return $result;
    }
}
