<?php

namespace ItsDangerous\Signer;

abstract class SigningAlgorithm {
    abstract public function get_signature($key, $value);

    public function verify_signature($key, $value, $sig) {
        return constant_time_compare($sig, $this->get_signature($key, $value));
    }
}
