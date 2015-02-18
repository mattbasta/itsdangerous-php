<?php

define("EPOCH", 1293840000);

function is_text_serializer($serializer) {
    return is_string($serializer->dumps(array()));
}

function constant_time_compare($val1, $val2) {
    $s = strlen($val1);
    if($s != strlen($val2)) return false;
    $result = 0;
    for($i = 0; $i < $s; $i++)
        $result |= ord($val1[$i]) ^ ord($val2[$i]);
    return $result == 0;
}

class BadData extends Exception {}
class BadPayload extends BadData {
    public $original_error = null;
    public function __construct($message, $original_error=null) {
        parent::__construct($message);
        $this->original_error = $original_error;
    }
}
class BadSignature extends BadData {
    public $payload = null;
    public function __construct($message, $payload=null) {
        parent::__construct($message);
        $this->payload = $payload;
    }
}
class BadTimeSignature extends BadData {
    public $payload = null;
    public $date_signed = null;
    public function __construct($message, $payload=null, $date_signed=null) {
        parent::__construct($message);
        $this->payload = $payload;
        $this->date_signed = $date_signed;
    }
}
class SignatureExpired extends BadTimeSignature {}


function base64_encode_($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64_decode_($data) {
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

abstract class SigningAlgorithm {
    abstract public function get_signature($key, $value);

    public function verify_signature($key, $value, $sig) {
        return constant_time_compare($sig, $this->get_signature($key, $value));
    }
}

class NoneAlgorithm extends SigningAlgorithm {
    public function get_signature($key, $value) {
        return '';
    }
}

class HMACAlgorithm extends SigningAlgorithm {

    public static $default_digest_method = 'sha1';

    private $digest_method;

    public function __construct($digest_method=null) {
        if (is_null($digest_method)) {
            $digest_method = self::$default_digest_method;
        }
        $this->digest_method = $digest_method;
    }

    public function get_signature($key, $value) {
        return hash_hmac($this->digest_method, $value, $key, true);
    }
}


class Signer {

    public static $default_digest_method = 'sha1';
    public static $default_key_derivation = 'django-concat';

    protected $secret_key;
    protected $sep;
    protected $salt;
    protected $key_derivation;
    protected $digest_method;
    protected $algorithm;

    public function __construct($secret_key, $salt=null, $sep='.', $key_derivation=null, $digest_method=null, $algorithm=null) {
        $this->secret_key = $secret_key;
        $this->sep = $sep;
        $this->salt = is_null($salt) ? 'itsdangerous.Signer' : $salt;
        $this->key_derivation = is_null($key_derivation) ? self::$default_key_derivation : $key_derivation;
        $this->digest_method = is_null($digest_method) ? self::$default_digest_method : $digest_method;
        $this->algorithm = is_null($algorithm) ? new HMACAlgorithm($this->digest_method) : $algorithm;
    }

    protected function digest($input) {
        return hash($this->digest_method, $input, true);
    }

    public function derive_key() {
    	switch ($this->key_derivation) {
    	    case 'concat':
                return $this->digest($this->salt . $this->secret_key);
            case 'django-concat':
                return $this->digest($this->salt . 'signer' . $this->secret_key);
            case 'hmac':
                return hash_hmac($this->digest_method, $this->salt, $this->secret_key, true);
            default:
                throw new Exception("Unknown key derivation method");
    	}
    }

    public function get_signature($value) {
        $key = $this->derive_key();
        $sig = $this->algorithm->get_signature($key, $value);
        return base64_encode_($sig);
    }

    public function sign($value) {
        return $value . $this->sep . $this->get_signature($value);
    }

    public function verify_signature($value, $sig) {
        $key = $this->derive_key();
        $sig = base64_decode_($sig);
        return $this->algorithm->verify_signature($key, $value, $sig);
    }

    public function unsign($signed_value) {
        if(strpos($signed_value, $this->sep) === false)
            throw new BadSignature("No \"{$this->sep}\" found in value");
        $exploded = explode($this->sep, $signed_value);
        $sig = array_pop($exploded);
        $value = implode($this->sep, $exploded);
        if($this->verify_signature($value, $sig))
            return $value;
        throw new BadSignature("Signature \"{$sig}\" does not match", $value);
    }

    public function validate($signed_value) {
        try {
            $this->unsign($signed_value);
            return true;
        } catch(BadSignature $ex) {
            return false;
        }
    }

}

class TimestampSigner extends Signer {

    public function get_timestamp() {
        return time() - EPOCH;
    }

    public function timestamp_to_datetime($ts) {
        return DateTime::createFromFormat("U", $ts + EPOCH, new DateTimeZone("UTC"));
    }

    public function sign($value) {
        $timestamp = base64_encode_(int_to_bytes($this->get_timestamp()));
        $value = $value . $this->sep . $timestamp;
        return $value . $this->sep . $this->get_signature($value);
    }

    public function unsign($value, $max_age=null, $return_timestamp=false) {

        try {
            $result = parent::unsign($value);
            $sig_err = null;
        } catch (BadSignature $ex) {
            $sig_err = $ex;
            $result = $ex->payload;
        }

        if(strpos($result, $this->sep) === false) {
            if (!is_null($sig_err)) {
                throw $sig_err;
            }
            throw new BadTimeSignature("timestamp missing", $result);
        }

        $exploded = explode($this->sep, $result);
        $timestamp = array_pop($exploded);
        $value = implode($this->sep, $exploded);

        try {
            $timestamp = bytes_to_int(base64_decode_($timestamp));
        } catch (Exception $ex) {
            $timestamp = null;
        }

        # Signature is *not* okay.  Raise a proper error now that we have
        # split the value and the timestamp.
        if (!is_null($sig_err))
            throw new BadTimeSignature((string) $sig_err, $value, $timestamp);

        # Signature was okay but the timestamp is actually not there or
        # malformed.  Should not happen, but well.  We handle it nonetheless
        if (is_null($timestamp))
            throw new BadTimeSignature('Malformed timestamp', $value);

        if(!is_null($max_age)) {
            $age = $this->get_timestamp() - $timestamp;
            if($age > $max_age)
                throw new SignatureExpired(
                    "Signature age $age > $max_age seconds",
                    $value,
                    $this->timestamp_to_datetime($timestamp));
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

    public static $default_signer = 'Signer';
    public static function default_serializer() {return new simplejson();}

    protected $secret_key;
    protected $salt;
    protected $serializer;
    protected $is_text_serializer;

    public function __construct($secret_key, $salt="itsdangerous", $serializer=null, $signer=null) {
        $this->secret_key = $secret_key;
        $this->salt = $salt;
        if(is_null($serializer))
            $serializer = self::default_serializer();
        $this->serializer = $serializer;
        $this->is_text_serializer = is_text_serializer($this->serializer);
        if (is_null($signer))
            $signer = self::$default_signer;
        $this->signer = $signer;
    }

    public function load_payload($payload, $serializer=null) {
        if (is_null($serializer)) {
            $serializer = $this->serializer;
            $is_text = $this->is_text_serializer;
        } else {
            $is_text = is_text_serializer($serializer);
        }
        try {
            return $serializer->loads($payload);
        } catch (Exception $ex) {
            throw new BadPayload(
                "Could not load the payload because an exception occurred " +
                "on unserializing the data.", $ex);
        }
    }

    public function dump_payload($obj) {
        return $this->serializer->dumps($obj);
    }

    public function make_signer($salt=null) {
        if (is_null($salt)) {
            $salt = $this->salt;
        }
        $signer = $this->signer;
        return new $signer($this->secret_key, $salt);
    }

    public function dumps($obj, $salt=null) {
        return $this->make_signer($salt)->sign($this->dump_payload($obj));
    }

    public function dump($obj, $f, $salt=null) {
        fwrite($f, $this->dumps($obj, $salt));
    }

    public function loads($s, $salt=null) {
        return $this->load_payload($this->make_signer($salt)->unsign($s));
    }

    public function load($f, $salt=null) {
        return $this->loads(fread($f, filesize($f)), $salt);
    }

    public function loads_unsafe($s, $salt=null) {
        try {
            return array(true, $this->loads($s, $salt));
        } catch (Exception $ex) {
            if (is_null($ex->payload)) {
                return array(false, null);
            }
            try {
                return array(false, self.load_payload($ex->payload));
            } catch (BadPayload $ex) {
                return array(false, null);
            }
        }
    }

    public function load_unsafe($f, $salt=null) {
        return $this->loads_unsafe(fread($f, filesize($f)), $salt);
    }

    /*
    public function _urlsafe_load_payload($payload){
        $decompress = false;
        if ($payload[0] == '.'){
            $payload = substr($payload, 1);
            $decompress = true;
        }
        $json = base64_decode_($payload);
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
        $base64d = base64_encode_($json);
        if ($is_compressed){
            $base64d = '.' . $base64d;
        }
        return $base64d;
    }
    */
}


class TimedSerializer extends Serializer {

    public static $default_signer = 'Signer';

    public function loads($s, $max_age=null, $return_timestamp=false, $salt=null) {
        list($base64d, $timestamp) = $this->make_signer($salt)->unsign($s, $max_age, true);
        $payload = $this->load_payload($base64d);
        if($return_timestamp) {
            return array($payload, $timestamp);
        } else {
            return $payload;
        }
    }

    public function load($f, $max_age=null, $return_timestamp=false, $salt=null) {
        return $this->loads(fread($f, filesize($f)), $max_age, $return_timestamp, $salt);
    }

    public function loads_unsafe($s, $max_age=null, $return_timestamp=false, $salt=null) {
        try {
            return array(true, $this->loads($s, $max_age, $return_timestamp, $salt));
        } catch (Exception $ex) {
            if (is_null($ex->payload)) {
                return array(false, null);
            }
            try {
                return array(false, self.load_payload($ex->payload));
            } catch (BadPayload $ex) {
                return array(false, null);
            }
        }
    }

    public function load_unsafe($f, $max_age=null, $return_timestamp=false, $salt=null) {
        return $this->loads_unsafe(fread($f, filesize($f)), $max_age, $return_timestamp, $salt);
    }

}

/*
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
*/
