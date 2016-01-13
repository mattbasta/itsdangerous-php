<?php

define("EPOCH", 1293840000);
require 'vendor/autoload.php';

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




use ItsDangerous\Signer\Serializer;

/**
 * @codeCoverageIgnore
 * this thing doesn't do anything - I'm so confused
 */
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
