<?php
/**
 * php7 AES and chacha AEAD 加密解密类
 * @author Wood <wood@example.com>
 */
class Encryptor{
    protected $_key;
    protected $_cipher;
    protected $_decipher;
    protected $_cipherIv;
    protected $_bytesToKeyResults = [];
    protected $_method;
    protected $_ivSent;
    protected $_onceMode;
    protected static $_methodSupported = [
        'none' => [16, 0],
        'aes-128-cfb' => [16, 16],
        'aes-192-cfb' => [24, 16],
        'aes-256-cfb' => [32, 16],
        'aes-128-gcm' => [16, 16],
        'aes-192-gcm' => [24, 24],
        'aes-256-gcm' => [32, 32], //PHP >= 7.2.0
        'chacha20-poly1305' => [32, 32], //PHP >= 7.2.0
        'chacha20-ietf-poly1305' => [32, 32], //PHP >= 7.2.0
        'xchacha20-ietf-poly1305' => [32, 32], //PHP >= 7.2.0
    ];
    //
    public function __construct($key, $method, $onceMode = false){
        $this->_key = $key;
        $this->_method = $method;
        $this->_ivSent = false;
        $this->_onceMode = $onceMode;
        $chachaArr = ['chacha20-poly1305', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305'];
        if(!isset(self::$_methodSupported[$this->_method])){
            echo 'encrypt method '.$this->_method.' is not exist !';
        }elseif(in_array($this->_method, $chachaArr) && !function_exists('sodium_increment')){
            echo 'encrypt method '.$this->_method.' needs sodium, please enable sodium expansion !';
        }
        $salt_len = $this->getCipherLen($this->_method);
        $salt_len = $salt_len[1];
        $salt = openssl_random_pseudo_bytes($salt_len);
        $this->_cipher = $this->getCipher($this->_key, $this->_method, 1, $salt);
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
        $m = $this->getCipherLen($method);
        if($m){
            $ref = $this->EVPBytesToKey($password, $m[0], $m[1]);
            $key = $ref[0];
            $iv_ = $ref[1];
            if($iv == null){
                $iv = $iv_;
            }
            $iv = substr($iv, 0, $m[1]);
            if($op === 1){
                $this->_cipherIv = $iv;
            }
            if($this->checkAEADMethod($method)){
                $salt = $iv;
                if($op === 1){
                    return new AEADEncipher($method, $key, $salt, $this->_onceMode);
                }else{
                    return new AEADDecipher($method, $key, $salt, $this->_onceMode);
                }
            }elseif($method == 'none'){
                return new NoneEncipher();
            }else{
                if($op === 1){
                    return new Encipher($method, $key, $iv);
                }else{
                    return new Decipher($method, $key, $iv);
                }
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
        return isset(self::$_methodSupported[$method]) ? self::$_methodSupported[$method] : null;
    }
    //
    protected function checkAEADMethod($method){
        $mArr = ['aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'chacha20-poly1305', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305'];
        if(in_array($method, $mArr)){
            return true;
        }
        return false;
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
//
class NoneEncipher{
    public function update($buffer){
        return $buffer;
    }
}
//
class AEADEncipher{
    //
    const CHUNK_SIZE_LEN = 2;
    const AEAD_TAG_LEN = 16;
    const CRYPTO_ERROR = -1;
    const CRYPTO_NEED_MORE = 0;
    const CRYPTO_OK = 1;
    const CHUNK_SIZE_MASK = 0x3FFF;
    //
    protected $_algorithm;
    protected $_aead_tail;
    protected $_aead_subkey;
    protected $_aead_iv;
    protected $_aead_chunk_id;
    protected $_aead_encipher_all;
    protected $_sodium_support;
    protected static $_methodSupported = [
        'aes-128-gcm'=> [16, 12],
        'aes-192-gcm'=> [24, 12],
        'aes-256-gcm'=> [32, 12],
        'chacha20-poly1305'=> [32, 8],
        'chacha20-ietf-poly1305'=> [32, 12],
        'xchacha20-ietf-poly1305'=> [32, 24],
    ];
    //
    public function __construct($algorithm, $key, $salt, $all = false){
        $this->_algorithm = $algorithm;
        $this->_aead_tail = '';
        $iv_len = self::$_methodSupported[$algorithm][1];
        $this->_aead_iv = str_repeat("\x00", $iv_len);
        $this->_aead_subkey = hash_hkdf('sha1', $key, strlen($key), 'ss-subkey', $salt); //subkey生成
        $this->_aead_chunk_id = 0;
        $this->_aead_encipher_all = $all;
        $this->_sodium_support = function_exists('sodium_increment') ? true : false;
    }
    //
    public function update($data){
        if($this->_aead_encipher_all){ //UDP
            $res = $this->aead_encrypt_all($this->_aead_iv, $this->_aead_subkey, $data);
            if($res === static::CRYPTO_ERROR){
                return '';
            }
            return $data;
        }
        //TCP
        $result = '';
        while(strlen($data) > 0){
            $tmp = '';
            $err = $this->aead_chunk_encrypt($this->_aead_iv, $this->_aead_subkey, $data, $tmp);
            if($err === static::CRYPTO_ERROR){
                return '';
            }
            $result .= $tmp;
        }
        return $result;
    }
    //
    protected function aead_encrypt_all(&$iv, $subkey, &$buffer){
        $buffer = $this->aead_encrypt($buffer, '', $iv, $subkey);
        return static::CRYPTO_OK;
    }
    //
    protected function aead_chunk_encrypt(&$iv, $subkey, &$buffer, &$result){
        $plen = strlen($buffer);
        if($plen > static::CHUNK_SIZE_MASK){
            $plen = static::CHUNK_SIZE_MASK;
        }
        $data = substr($buffer, 0, $plen);
        $plen_bin = pack('n', $plen);
        $result .= $this->aead_encrypt($plen_bin, '', $iv, $subkey);
        if(strlen($result) != static::AEAD_TAG_LEN + static::CHUNK_SIZE_LEN){
            return static::CRYPTO_ERROR;
        }
        if($this->_sodium_support){
            sodium_increment($iv);
        }else{
            $this->nonce_increment($iv);
        }
        $result .= $this->aead_encrypt($data, '', $iv, $subkey);
        if(strlen($result) != 2 * static::AEAD_TAG_LEN + static::CHUNK_SIZE_LEN + $plen){
            return static::CRYPTO_ERROR;
        }
        if($this->_sodium_support){
            sodium_increment($iv);
        }else{
            $this->nonce_increment($iv);
        }
        $this->_aead_chunk_id++;
        $buffer = substr($buffer, $plen);
        return static::CRYPTO_OK;
    }
    //
    protected function aead_encrypt($buffer, $ad, $nonce, $key){
        switch($this->_algorithm){
            case 'aes-128-gcm':
            case 'aes-192-gcm':
            case 'aes-256-gcm':
                if($this->_sodium_support && $this->_algorithm == 'aes-256-gcm'){
                    return sodium_crypto_aead_aes256gcm_encrypt($buffer, $ad, $nonce, $key);
                }
                $tag = '';
                $data = openssl_encrypt($buffer, $this->_algorithm, $key, OPENSSL_RAW_DATA, $nonce, $tag, $ad);
                return $data.$tag;
            case 'chacha20-poly1305':
                return $this->_sodium_support ? sodium_crypto_aead_chacha20poly1305_encrypt($buffer, $ad, $nonce, $key) : '';
            case 'chacha20-ietf-poly1305':
                return $this->_sodium_support ? sodium_crypto_aead_chacha20poly1305_ietf_encrypt($buffer, $ad, $nonce, $key) : '';
            case 'xchacha20-ietf-poly1305':
                return $this->_sodium_support ? sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($buffer, $ad, $nonce, $key) : '';
            default:
                return '';
        }
    }
    //
    protected function nonce_increment(&$nonce){
        $c = 1;
        $len = strlen($nonce);
        for($i = 0; $i < $len; $i++){
            $c += ord($nonce[$i]);
            $nonce[$i] = chr($c & 0xff);
            $c >>= 8;
        }
    }
}

class AEADDecipher extends AEADEncipher{
    //
    public function update($data){
        //UDP
        if($this->_aead_encipher_all){
            $res = $this->aead_decrypt_all($this->_aead_iv, $this->_aead_subkey, $data);
            if($res === static::CRYPTO_ERROR){
                return '';
            }
            return $data;
        }
        //TCP
        $tl = strlen($this->_aead_tail);
        if($tl){
            $data = $this->_aead_tail.$data;
            $this->_aead_tail = '';
        }
        $result = '';
        while(strlen($data) > 0){
            $res = $this->aead_chunk_decrypt($this->_aead_iv, $this->_aead_subkey, $data, $result);
            if($res === static::CRYPTO_ERROR){
                return '';
            }elseif($res === static::CRYPTO_NEED_MORE){
                if(strlen($data) == 0){
                    return '';
                }else{
                    $this->_aead_tail .= $data;
                    break;
                }
            }
        }
        return $result;
    }
    //
    public function aead_decrypt_all(&$iv, $subkey, &$buffer){
        if(strlen($buffer) <= static::AEAD_TAG_LEN){ //验证chunk长度
            return static::CRYPTO_ERROR;
        }
        $buffer = $this->aead_decrypt($buffer, '', $iv, $subkey);
        return static::CRYPTO_OK;
    }
    //
    protected function aead_chunk_decrypt(&$iv, $subkey, &$buffer, &$result){
        if(strlen($buffer) <= 2 * static::AEAD_TAG_LEN + static::CHUNK_SIZE_LEN){ //验证chunk长度
            return static::CRYPTO_NEED_MORE;
        }
        $payload_length_enc_length = static::AEAD_TAG_LEN + static::CHUNK_SIZE_LEN;
        $payload_length_enc = substr($buffer, 0, $payload_length_enc_length);
        $mlen = $this->aead_decrypt($payload_length_enc, '', $iv, $subkey);
        if(strlen($mlen) != static::CHUNK_SIZE_LEN){
            return static::CRYPTO_ERROR;
        }
        $payload_length = unpack('n', $mlen);
        $payload_length = intval($payload_length[1]) & static::CHUNK_SIZE_MASK;
        $payload_enc_length = $payload_length + static::AEAD_TAG_LEN;
        if(strlen($buffer) - $payload_length_enc_length < $payload_enc_length){ //验证payload长度
            return static::CRYPTO_NEED_MORE;
        }
        $buffer = substr($buffer, $payload_length_enc_length);
        $payload_enc = substr($buffer, 0, $payload_enc_length);
        $buffer = substr($buffer, $payload_enc_length);
        if($this->_sodium_support){
            sodium_increment($iv);
        }else{
            $this->nonce_increment($iv);
        }
        $result .= $this->aead_decrypt($payload_enc, '', $iv, $subkey);
        if($this->_sodium_support){
            sodium_increment($iv);
        }else{
            $this->nonce_increment($iv);
        }
        $this->_aead_chunk_id++;
        return static::CRYPTO_OK;
    }
    //
    protected function aead_decrypt($buffer, $ad, $nonce, $key){
        switch($this->_algorithm){
            case 'aes-128-gcm':
            case 'aes-192-gcm':
            case 'aes-256-gcm':
                if($this->_sodium_support && $this->_algorithm == 'aes-256-gcm'){
                    return sodium_crypto_aead_aes256gcm_decrypt($buffer, $ad, $nonce, $key);
                }
                $data_len = strlen($buffer) - static::AEAD_TAG_LEN;
                $data = substr($buffer, 0, $data_len);
                $tag = substr($buffer, $data_len);
                return openssl_decrypt($data, $this->_algorithm, $key, OPENSSL_RAW_DATA, $nonce, $tag, $ad);
            case 'chacha20-poly1305':
                return $this->_sodium_support ? sodium_crypto_aead_chacha20poly1305_decrypt($buffer, $ad, $nonce, $key) : '';
            case 'chacha20-ietf-poly1305':
                return $this->_sodium_support ? sodium_crypto_aead_chacha20poly1305_ietf_decrypt($buffer, $ad, $nonce, $key) : '';
            case 'xchacha20-ietf-poly1305':
                return $this->_sodium_support ? sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($buffer, $ad, $nonce, $key) : '';
            default :
                return '';
        }
    }
}