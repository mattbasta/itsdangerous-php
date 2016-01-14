<?php

namespace ItsDangerous\Signer;

use ItsDangerous\BadData\BadSignature;
use ItsDangerous\BadData\BadTimeSignature;
use ItsDangerous\BadData\SignatureExpired;

use Carbon\Carbon;

class TimestampSigner extends Signer {

    public function get_timestamp() {
        return Carbon::now()->timestamp - EPOCH;
    }

    public function timestamp_to_datetime($ts) {
        return \DateTime::createFromFormat("U", $ts + EPOCH, new \DateTimeZone("UTC"));
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

        $timestamp = bytes_to_int(base64_decode_($timestamp));

        # Signature is *not* okay.  Raise a proper error now that we have
        # split the value and the timestamp.
        if (!is_null($sig_err)) {
            throw new BadTimeSignature((string) $sig_err, $value, $timestamp);
        }

        # Signature was okay but the timestamp is actually not there or
        # malformed.  Should not happen, but well.  We handle it nonetheless
        if (is_null($timestamp))
            throw new BadTimeSignature('Malformed timestamp', $value);

        if(!is_null($max_age)) {
            $age = $this->get_timestamp() - $timestamp;
            if($age > $max_age) {
                throw new SignatureExpired(
                    "Signature age $age > $max_age seconds",
                    $value,
                    $this->timestamp_to_datetime($timestamp));
            }
        }

        if($return_timestamp) {
            return array($value, $this->timestamp_to_datetime($timestamp));
        }
        return $value;
    }

    public function validate($signed_value, $max_age=null) {
        try {
            $this->unsign($signed_value, $max_age);
            return true;
        } catch(\Exception $ex) {
            return false;
        }
    }

}
