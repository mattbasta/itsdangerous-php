<?php

define("EPOCH", 1293840000);

function constant_time_compare($val1, $val2) {
    $s = strlen($val1);
    if($s != strlen($val2)) return false;
    $result = 0;
    for($i = 0; $i < $s; $i++)
        $result |= ord($val1[$i]) ^ ord($val2[$i]);
    return $result == 0;
}

function base64_encode_url($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64_decode_url($data) {
    return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
}

function int_to_bytes($num) {
    $output = "";
    while($num > 0) {
        $output .= chr($num & 0xff);
        $num >>= 8;
    }
    return strrev($output);
}

function bytes_to_int($bytes) {
    $output = 0;
    foreach(str_split($bytes) as $byte) {
        if($output > 0)
            $output <<= 8;
        $output += ord($byte);
    }
    return $output;
}

class Signer {

    public static function digest_method($input) {return sha1($input, true);}

    public function __construct($secret_key, $salt=null, $sep='.') {
        $this->secret_key = $secret_key;
        $this->sep = $sep;
        $this->salt = is_null($salt) ? __FILE__ : $salt;
    }

    public function get_signature($value) {
        $key = self::digest_method($this->salt . 'signer' . $this->secret_key);
        $mac = hash_hmac("sha1", $value, $key, true);
        return base64_encode_url($mac);
    }

    public function sign($value) {
        return $value . $this->sep . $this->get_signature($value);
    }

    public function unsign($signed_value) {
        if(strpos($signed_value, $this->sep) === false)
            throw new Exception("Bad Signature: No \"{$this->sep}\" found in value");
        $exploded = explode($this->sep, $signed_value);
        $sig = array_pop($exploded);
        $value = implode($this->sep, $exploded);
        if(constant_time_compare($sig, $this->get_signature($value)))
            return $value;
        throw new Exception("Bad Signature: Signature \"{$sig}\" does not match");
    }

    public function validate($signed_value) {
        try {
            $this->unsign($signed_value);
            return true;
        } catch(Exception $ex) {
            return false;
        }
    }

}

class TimestampSigner extends Signer {

    public function get_timestamp() {
        return time() - EPOCH;
    }

    public function timestamp_to_datetime($ts) {
        return new DateTime($ts + EPOCH, new DateTimeZone("UTC"));
    }

    public function sign($value) {
        $timestamp = base64_encode_url(int_to_bytes($this->get_timestamp()));
        $value = $value . $this->sep . $timestamp;
        return $value . $this->sep . $this->get_signature($value);
    }

    public function unsign($value, $max_age=null, $return_timestamp=false) {
        $result = parent::unsign($value);
        if(strpos($result, $this->sep) === false)
            throw new Exception("Bad Signature: timestamp missing");

        $exploded = explode($this->sep, $result);
        $timestamp = array_pop($exploded);
        $value = implode($this->sep, $exploded);

        $timestamp = bytes_to_int(base64_decode_url($timestamp));
        if(!is_null($max_age)) {
            $age = $this->get_timestamp() - $timestamp;
            if($age > $max_age)
                throw new Exception("Signature Expired: Signature age $age > $max_age seconds");
        }
        if($return_timestamp)
            return array($value, $this->timestamp_to_datetime($timestamp));
        return $value;
    }

    public function validate($signed_value, $max_age=null) {
        try {
            $this->unsign($signed_value, $max_age);
            return true;
        } catch(Exception $ex) {
            return false;
        }
    }

}

class simplejson {

    public function loads($input) {return json_decode($input, true);}
    public function dumps($input) {return json_encode($input);}

}

class Serializer {

    public static function default_serializer() {return new simplejson();}

    public function __construct($secret_key, $salt="itsdangerous", $serializer=null) {
        $this->secret_key = $secret_key;
        $this->salt = $salt;
        if(is_null($serializer))
            $serializer = self::default_serializer();
        $this->serializer = $serializer;
    }

    public function load_payload($payload) {
        return $this->serializer->loads($payload);
    }

    public function dump_payload($obj) {
        return $this->serializer->dumps($obj);
    }

    public function make_signer() {
        return new Signer($this->secret_key, $this->salt);
    }

    public function dumps($obj) {
        return $this->make_signer()->sign($this->dump_payload($obj));
    }

    public function dump($obj, $f) {
        fwrite($f, $this->dumps($obj));
    }

    public function loads($s) {
        return $this->load_payload($this->make_signer()->unsign($s));
    }

    public function load($f) {
        return $this->loads(fread($f, filesize($f)));
    }
    
    public function _urlsafe_load_payload($payload){
        $decompress = false;
        if ($payload[0] == '.'){
            $payload = substr($payload, 1);
            $decompress = true;
        }
        $json = base64_decode_url($payload);
        if ($decompress){
            $json = gzuncompress($json);
            
        }
        return $json;
    }
    
    public function _urlsafe_dump_payload($json){
        $is_compressed = false;
        $compressed = gzcompress($json);
        if (strlen($compressed) < strlen($json) - 1){
            $json = $compressed;
            $is_compressed = true;
        }
        $base64d = base64_encode_url($json);
        if ($is_compressed){
            $base64d = '.' . $base64d;    
        }
        return $base64d;
    }

}


class TimedSerializer extends Serializer {

    public function make_signer() {
        return new TimestampSigner($this->secret_key, $this->salt);
    }

    public function loads($s, $max_age=null, $return_timestamp=false) {
        if($return_timestamp) {
            list($base64d, $timestamp) = $this->make_signer()->unsign($s, $max_age, true);
            return array($this->load_payload($base64d), $timestamp);
        } else {
            $base64d = $this->make_signer()->unsign($s, $max_age);
            return $this->load_payload($base64d);
        }
    }

}

class URLSafeSerializer extends Serializer {
    	
    public function load_payload($payload){
        return parent::load_payload($this->_urlsafe_load_payload($payload));
    }
	
    public function dump_payload($obj){
        return $this->_urlsafe_dump_payload(parent::dump_payload($obj));
    }
    
}

class URLSafeTimedSerializer extends TimedSerializer {
		
    public function load_payload($payload){
        return parent::load_payload($this->_urlsafe_load_payload($payload));
    }
	
    public function dump_payload($obj){
        return $this->_urlsafe_dump_payload(parent::dump_payload($obj));
    }
    
}