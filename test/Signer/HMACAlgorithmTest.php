<?php

use ItsDangerous\Signer\HMACAlgorithm;

class HMACAlgorithmTest extends PHPUnit_Framework_TestCase
{

    public function testGetSignature_noDigestProvided_shouldDefaultToSHA1()
    {
        $algo = new HMACAlgorithm();

        $hash = $algo->get_signature('secret', 'hello');

		$hash = base64_encode($hash);
        $this->assertEquals('URIFXAX5RPhXVe/FzYlw4ZTp9Fs=', $hash);
    }

    public function testGetSignature_md5DigestRequested_shouldHashMD5()
    {
        $algo = new HMACAlgorithm('md5');

        $hash = $algo->get_signature('secret', 'hello');

		$hash = base64_encode($hash);
        $this->assertEquals('ut5jhjxh7QsxZYBuzWrO/A==', $hash);
    }

}
