<?php

namespace ItsDangerous\Signer;

use ItsDangerous\BadData\BadPayload;

class Serializer {

    public static $default_signer = 'ItsDangerous\Signer\Signer';
    public static function default_serializer() {return new SimpleJsonSerializer();}

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
            // @codeCoverageIgnoreStart
            // $is_text is never used for that matter, is_text_serializer
            // doesn't seemed to be used outside of this
            $is_text = is_text_serializer($serializer);
            // @codeCoverageIgnoreEnd
        }
        try {
            return $serializer->loads($payload);
        } catch (\Exception $ex) {
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

    // @codeCoverageIgnoreStart
    // lolwut - filesize of a file pointer or fread on a filename?
    public function load($f, $salt=null) {
        return $this->loads(fread($f, filesize($f)), $salt);
    }
    // @codeCoverageIgnoreEnd

    public function loads_unsafe($s, $salt=null) {
        try {
            return array(true, $this->loads($s, $salt));
        } catch (\Exception $ex) {
            if (empty($ex->payload)) {
                return array(false, null);
            }
            try {
                return array(false, $this->load_payload($ex->payload));
            // @codeCoverageIgnoreStart
            // I'm confused by the circular logic here - we just caught
            // and exception from loads (maybe with a salt), and we got
            // a payload in the exception, so we're going to call something
            // that doesn't do much but call loads again and maybe catch
            // an exception which would mean the data's garbage?
            } catch (BadPayload $ex) {
                return array(false, null);
            }
            // @codeCoverageIgnoreEnd
        }
    }

    // @codeCoverageIgnoreStart
    // broken because same reason load is broken
    public function load_unsafe($f, $salt=null) {
        return $this->loads_unsafe(fread($f, filesize($f)), $salt);
    }
    // @codeCoverageIgnoreEnd

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
