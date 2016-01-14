<?php

use ItsDangerous\Signer\NoneAlgorithm;

class NoneAlgorithmTest extends PHPUnit_Framework_TestCase
{

    public function testGetSignature_shouldReturnEmptySignature()
    {
        $algo = new NoneAlgorithm();

        $sig = $algo->get_signature('secret', 'hello');

        $this->assertEquals('', $sig);
    }

}
