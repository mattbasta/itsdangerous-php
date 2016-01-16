<?php

use ItsDangerous\Signer\SigningAlgorithm;

class SigningAlgorithmTest extends PHPUnit_Framework_TestCase
{

	public function testConstantTimeCompare_unequalLengths_returnFalse()
	{
		$stub = $this->getMockForAbstractClass('ItsDangerous\Signer\SigningAlgorithm');

		$equal = $stub->constant_time_compare('four', 'sixsix');

		$this->assertFalse($equal);
	}

	// TODO: timing test to assert that constant time means that it
	// doesn't short circuit?
}
