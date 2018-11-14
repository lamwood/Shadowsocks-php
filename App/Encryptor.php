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
        'aes-128-cfb'=> [16, 16],
        'aes-192-cfb'=> [24, 16],
        'aes-256-cfb'=> [32, 16],
        'aes-128-gcm'=> [16, 16],
        'aes-192-gcm'=> [24, 24],
        'aes-256-gcm'=> [32, 32], //PHP >= 7.2.0
        'chacha20-poly1305'=> [32, 32], //PHP >= 7.2.0
        'chacha20-ietf-poly1305'=> [32, 32], //PHP >= 7.2.0
        'xchacha20-ietf-poly1305'=> [32, 32], //PHP >= 7.2.0
    ];
    //
    public function __construct($key, $method, $onceMode = false){
        $this->_key = $key;
        $this->_method = $method;
        $this->_ivSent = false;
        $this->_onceMode = $onceMode;
        if(!isset(self::$_methodSupported[$this->_method])){
            return null;
        }
        if($this->checkAEADMethod($this->_method)){
            $salt_len = $this->getCipherLen($this->_method);
            $salt_len = $salt_len[1];
            $salt = openssl_random_pseudo_bytes($salt_len);
            $this->_cipher = $this->getCipher($this->_key, $this->_method, 1, $salt);
        }else{
            $iv_size = openssl_cipher_iv_length($this->_method); 
            $iv = openssl_random_pseudo_bytes($iv_size); 
            $this->_cipher = $this->getcipher($this->_key, $this->_method, 1, $iv);
        }
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
        $method = strtolower($method);
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
class AEADEncipher{
    protected $_algorithm;
    protected $_aead_tail;
    protected $_aead_subkey;
    protected $_aead_iv;
    protected $_aead_chunk_id;
    protected $_aead_encipher_all;
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
    }
    //
    public function update($data){
        if($this->_aead_encipher_all){ //UDP
            $res = $this->aead_encrypt_all($this->_aead_iv, $this->_aead_subkey, $data);
            if($res === false){
                return '';
            }
            return $data;
        }
        //TCP
        $result = '';
        while(strlen($data) > 0){
            $tmp = '';
            $err = $this->aead_chunk_encrypt($this->_aead_iv, $this->_aead_subkey, $data, $tmp);
            if($err === false){
                return '';
            }
            $result .= $tmp;
        }
        return $result;
    }
    //
    protected function aead_encrypt_all(&$iv, $subkey, &$buffer){
        $buffer = $this->aead_encrypt($buffer, '', $iv, $subkey);
        return true;
    }
    //
    protected function aead_chunk_encrypt(&$iv, $subkey, &$buffer, &$result){
        $plen = strlen($buffer);
        if($plen > 0x3FFF){//CHUNK_SIZE_MASK
            $plen = 0x3FFF;
        }
        $data = substr($buffer, 0, $plen);
        $plen_bin = pack('n', $plen);
        $result .= $this->aead_encrypt($plen_bin, '', $iv, $subkey);
        if(strlen($result) != 16 + 2){
            return false;
        }
        sodium_increment($iv);
        $result .= $this->aead_encrypt($data, '', $iv, $subkey);
        if(strlen($result) != 2 * 16 + 2 +$plen){
            return false;
        }
        sodium_increment($iv);
        $this->_aead_chunk_id++;
        $buffer = substr($buffer, $plen);
        return true;
    }
    //
    protected function aead_encrypt($buffer, $ad, $nonce, $key){
        switch($this->_algorithm){
            case 'aes-128-gcm':
            case 'aes-192-gcm':
                $tag = '';
                $data = openssl_encrypt($buffer, $this->_algorithm, $key, OPENSSL_RAW_DATA, $nonce, $tag, $ad);
                return $data.$tag;
            case 'aes-256-gcm':
                return sodium_crypto_aead_aes256gcm_encrypt($buffer, $ad, $nonce, $key);
            case 'chacha20-poly1305':
                return sodium_crypto_aead_chacha20poly1305_encrypt($buffer, $ad, $nonce, $key);
            case 'chacha20-ietf-poly1305':
                return sodium_crypto_aead_chacha20poly1305_ietf_encrypt($buffer, $ad, $nonce, $key);
            case 'xchacha20-ietf-poly1305':
                return sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($buffer, $ad, $nonce, $key);
            default:
                return '';
        }
    }
}

class AEADDecipher extends AEADEncipher{
    //
    public function update($data){
        //UDP
        if($this->_aead_encipher_all){
            $res = $this->aead_decrypt_all($this->_aead_iv, $this->_aead_subkey, $data);
            if($res === false){
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
            if($res === false){
                return '';
            }elseif($res === 0){
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
        if(strlen($buffer) <= 16){ //验证chunk长度
            return false;
        }
        $buffer = $this->aead_decrypt($buffer, '', $iv, $subkey);
        return true;
    }
    //
    protected function aead_chunk_decrypt(&$iv, $subkey, &$buffer, &$result){
        if(strlen($buffer) <= 2 * 16 + 2){ //验证chunk长度
            return 0;
        }
        $payload_length_enc_length = 16 + 2;
        $payload_length_enc = substr($buffer, 0, $payload_length_enc_length);
        $mlen = $this->aead_decrypt($payload_length_enc, '', $iv, $subkey);
        if(strlen($mlen) != 2){
            return false;
        }
        $payload_length = unpack('n', $mlen);
        $payload_length = intval($payload_length[1]) & 0x3FFF;
        $payload_enc_length = $payload_length + 16;
        if(strlen($buffer) - $payload_length_enc_length < $payload_enc_length){ //验证payload长度
            return 0;
        }
        $buffer = substr($buffer, $payload_length_enc_length);
        $payload_enc = substr($buffer, 0, $payload_enc_length);
        $buffer = substr($buffer, $payload_enc_length);
        sodium_increment($iv);
        $result .= $this->aead_decrypt($payload_enc, '', $iv, $subkey);
        sodium_increment($iv);
        $this->_aead_chunk_id++;
        return true;
    }
    //
    protected function aead_decrypt($buffer, $ad, $nonce, $key){
        switch($this->_algorithm){
            case 'aes-128-gcm':
            case 'aes-192-gcm':
                $data_len = strlen($buffer) - 16;
                $data = substr($buffer, 0, $data_len);
                $tag = substr($buffer, $data_len);
                return openssl_decrypt($data, $this->_algorithm, $key, OPENSSL_RAW_DATA, $nonce, $tag, $ad);
            case 'aes-256-gcm':
                return sodium_crypto_aead_aes256gcm_decrypt($buffer, $ad, $nonce, $key);
            case 'chacha20-poly1305':
                return sodium_crypto_aead_chacha20poly1305_decrypt($buffer, $ad, $nonce, $key);
            case 'chacha20-ietf-poly1305':
                return sodium_crypto_aead_chacha20poly1305_ietf_decrypt($buffer, $ad, $nonce, $key);
            case 'xchacha20-ietf-poly1305':
                return sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($buffer, $ad, $nonce, $key);
            default :
                return '';
        }
    }
}